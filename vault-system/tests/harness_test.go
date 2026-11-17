package tests

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"vault-system/pkg/vaultfile"
)

var binDir string

// TestMain builds fresh vault + vaultd binaries for the whole suite.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "vault-bin-")
	if err != nil {
		panic(err)
	}
	binDir = dir
	for _, b := range [][2]string{{"vault", "./cmd/vault"}, {"vaultd", "./cmd/auth-daemon"}} {
		cmd := exec.Command("go", "build", "-ldflags=-s -w", "-o", filepath.Join(dir, b[0]), b[1])
		cmd.Dir = ".."
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
		if out, err := cmd.CombinedOutput(); err != nil {
			fmt.Fprintf(os.Stderr, "build %s failed: %v\n%s", b[0], err, out)
			os.Exit(1)
		}
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

// env is an isolated HOME + XDG_RUNTIME_DIR for one test.
type env struct {
	t     *testing.T
	home  string
	run   string
	extra []string
}

func newEnv(t *testing.T) *env {
	t.Helper()
	// Short paths: Unix socket paths are limited to 108 bytes.
	home, err := os.MkdirTemp("", "vh-")
	if err != nil {
		t.Fatal(err)
	}
	run, err := os.MkdirTemp("", "vr-")
	if err != nil {
		t.Fatal(err)
	}
	os.Chmod(run, 0o700)
	e := &env{t: t, home: home, run: run}
	t.Cleanup(func() {
		if pid := e.pidFromFile(); pid > 0 {
			syscall.Kill(pid, syscall.SIGTERM)
			time.Sleep(100 * time.Millisecond)
			syscall.Kill(pid, syscall.SIGKILL)
		}
		os.RemoveAll(home)
		os.RemoveAll(run)
	})
	return e
}

func (e *env) vaultPath() string  { return vaultfile.PathFor(e.home, os.Getuid()) }
func (e *env) legacyPath() string { return filepath.Join(e.home, ".vault") }
func (e *env) sockPath() string   { return filepath.Join(e.run, "vault.sock") }

func (e *env) pidFromFile() int {
	b, err := os.ReadFile(filepath.Join(e.run, "vault.pid"))
	if err != nil {
		return 0
	}
	pid, _ := strconv.Atoi(strings.TrimSpace(string(b)))
	return pid
}

func (e *env) environ() []string {
	return append([]string{
		"HOME=" + e.home,
		"XDG_RUNTIME_DIR=" + e.run,
		"PATH=/usr/bin:/bin",
	}, e.extra...)
}

type result struct {
	stdout, stderr, tty string
	code                int
}

func (r result) String() string {
	return fmt.Sprintf("exit=%d\n--- stdout ---\n%s\n--- stderr ---\n%s\n--- tty ---\n%s", r.code, r.stdout, r.stderr, r.tty)
}

func exitCode(err error) int {
	if err == nil {
		return 0
	}
	if ee, ok := err.(*exec.ExitError); ok {
		return ee.ExitCode()
	}
	return -1
}

// vault runs the CLI without a controlling terminal (own session), with
// optional stdin.
func (e *env) vault(stdin string, args ...string) result {
	e.t.Helper()
	cmd := exec.Command(filepath.Join(binDir, "vault"), args...)
	cmd.Env = e.environ()
	cmd.Stdin = strings.NewReader(stdin)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	err := runWithTimeout(cmd, 30*time.Second)
	return result{stdout: out.String(), stderr: errb.String(), code: exitCode(err)}
}

func runWithTimeout(cmd *exec.Cmd, d time.Duration) error {
	if err := cmd.Start(); err != nil {
		return err
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		return err
	case <-time.After(d):
		cmd.Process.Kill()
		<-done
		return fmt.Errorf("timeout")
	}
}

// vaultTTY runs the CLI with a pseudo terminal as controlling terminal and
// types each of inputs after the next prompt (": ") appears on /dev/tty.
// This is how a human types a password; nothing goes through argv/env.
func (e *env) vaultTTY(inputs []string, args ...string) result {
	e.t.Helper()
	master, slave, err := openPTY()
	if err != nil {
		e.t.Fatalf("openpty: %v", err)
	}
	defer master.Close()

	cmd := exec.Command(filepath.Join(binDir, "vault"), args...)
	cmd.Env = e.environ()
	var out, errb bytes.Buffer
	cmd.Stdin, cmd.Stdout, cmd.Stderr = slave, &out, &errb
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	if err := cmd.Start(); err != nil {
		e.t.Fatal(err)
	}
	slave.Close()

	var mu sync.Mutex
	var ttyBuf bytes.Buffer
	go func() {
		b := make([]byte, 1024)
		for {
			n, err := master.Read(b)
			mu.Lock()
			ttyBuf.Write(b[:n])
			mu.Unlock()
			if err != nil {
				return
			}
		}
	}()
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	var waitErr error
	exited := false
	for i, in := range inputs {
		deadline := time.Now().Add(20 * time.Second)
		for !exited {
			mu.Lock()
			n := strings.Count(ttyBuf.String(), ": ")
			mu.Unlock()
			if n > i {
				break
			}
			select {
			case waitErr = <-done:
				exited = true
			case <-time.After(20 * time.Millisecond):
			}
			if time.Now().After(deadline) {
				cmd.Process.Kill()
				e.t.Fatalf("timeout waiting for prompt %d", i+1)
			}
		}
		if exited {
			break
		}
		master.Write([]byte(in + "\n"))
	}
	if !exited {
		select {
		case waitErr = <-done:
		case <-time.After(30 * time.Second):
			cmd.Process.Kill()
			waitErr = <-done
		}
	}
	time.Sleep(20 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	return result{stdout: out.String(), stderr: errb.String(), tty: ttyBuf.String(), code: exitCode(waitErr)}
}

func ioctl(fd, req uintptr, arg unsafe.Pointer) error {
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, fd, req, uintptr(arg)); e != 0 {
		return e
	}
	return nil
}

func openPTY() (*os.File, *os.File, error) {
	m, err := os.OpenFile("/dev/ptmx", os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		return nil, nil, err
	}
	var unlock int32
	if err := ioctl(m.Fd(), syscall.TIOCSPTLCK, unsafe.Pointer(&unlock)); err != nil {
		m.Close()
		return nil, nil, err
	}
	var n uint32
	if err := ioctl(m.Fd(), syscall.TIOCGPTN, unsafe.Pointer(&n)); err != nil {
		m.Close()
		return nil, nil, err
	}
	s, err := os.OpenFile("/dev/pts/"+strconv.Itoa(int(n)), os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		m.Close()
		return nil, nil, err
	}
	return m, s, nil
}

// --- assertions -----------------------------------------------------------

func mustOK(t *testing.T, r result, what string) {
	t.Helper()
	if r.code != 0 {
		t.Fatalf("FAIL %s:\n%s", what, r)
	}
}

func mustFail(t *testing.T, r result, wantErr, what string) {
	t.Helper()
	if r.code == 0 {
		t.Fatalf("FAIL %s: expected failure, got success:\n%s", what, r)
	}
	if !strings.Contains(r.stderr, wantErr) {
		t.Fatalf("FAIL %s: expected error containing %q:\n%s", what, wantErr, r)
	}
}

func mustEqual(t *testing.T, got, want, what string) {
	t.Helper()
	if got != want {
		t.Fatalf("FAIL %s: got %q, want %q", what, got, want)
	}
	t.Logf("PASS %s: %q", what, got)
}

func step(t *testing.T, format string, a ...any) {
	t.Helper()
	t.Logf("✔ "+format, a...)
}

func sshKeygen(t *testing.T, typ, bits, pass string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "key_"+typ)
	args := []string{"-q", "-t", typ, "-f", p, "-N", pass, "-C", "vault-test"}
	if bits != "" {
		args = append(args, "-b", bits)
	}
	if out, err := exec.Command("ssh-keygen", args...).CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen: %v\n%s", err, out)
	}
	return p
}

func pgrepVaultd(t *testing.T) []int {
	t.Helper()
	out, _ := exec.Command("pgrep", "-x", "-u", strconv.Itoa(os.Getuid()), "vaultd").Output()
	var pids []int
	for _, f := range strings.Fields(string(out)) {
		if p, err := strconv.Atoi(f); err == nil {
			pids = append(pids, p)
		}
	}
	return pids
}

func containsInt(xs []int, x int) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

// initPassword runs `vault init --password` typing pw twice.
func (e *env) initPassword(pw string) result {
	e.t.Helper()
	r := e.vaultTTY([]string{pw, pw}, "init", "--password")
	mustOK(e.t, r, "vault init --password")
	return r
}
