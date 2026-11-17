// Package spawn starts vaultd and hands it the vault key through a pipe.
//
// fd 3 (key pipe):    hex(key) + "\n" + "<keytype> <headlen> <idle s> <max s>\n",
//
//	then closed by the parent.
//
// fd 4 (status pipe): vaultd writes "OK\n" once it listens, or "ERR <msg>\n".
//
// The key never appears in argv or the environment. vaultd gets a minimal
// environment (HOME, XDG_RUNTIME_DIR) and its own session.
package spawn

import (
	"bufio"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	vcrypto "vault-system/pkg/crypto"
)

const DaemonName = "vaultd"

// Config is passed to vaultd together with the key.
type Config struct {
	KeyType     string
	HeadLen     int
	IdleTimeout time.Duration // 0 = disabled
	MaxLifetime time.Duration // 0 = disabled
}

// Line encodes c for the key pipe.
func (c Config) Line() string {
	return fmt.Sprintf("%s %d %d %d\n", c.KeyType, c.HeadLen,
		int64(c.IdleTimeout/time.Second), int64(c.MaxLifetime/time.Second))
}

// ParseConfig decodes Config.Line.
func ParseConfig(line string) (Config, error) {
	var c Config
	var idle, max int64
	if n, err := fmt.Sscanf(strings.TrimSpace(line), "%s %d %d %d", &c.KeyType, &c.HeadLen, &idle, &max); err != nil || n != 4 ||
		c.HeadLen <= 0 || idle < 0 || max < 0 {
		return c, errors.New("invalid config received on fd 3")
	}
	c.IdleTimeout, c.MaxLifetime = time.Duration(idle)*time.Second, time.Duration(max)*time.Second
	return c, nil
}

// FindDaemon looks for vaultd next to the running vault binary, then in PATH.
func FindDaemon() (string, error) {
	if exe, err := os.Executable(); err == nil {
		if real, err := filepath.EvalSymlinks(exe); err == nil {
			exe = real
		}
		p := filepath.Join(filepath.Dir(exe), DaemonName)
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			return p, nil
		}
	}
	p, err := exec.LookPath(DaemonName)
	if err != nil {
		return "", errors.New("vaultd binary not found (expected next to 'vault' or in PATH)")
	}
	return p, nil
}

// DaemonEnv is the environment vaultd is started with.
func DaemonEnv() []string {
	var env []string
	for _, k := range []string{"HOME", "XDG_RUNTIME_DIR"} {
		if v, ok := os.LookupEnv(k); ok {
			env = append(env, k+"="+v)
		}
	}
	return env
}

// Start launches vaultd with key and waits until it is serving. Returns its PID.
func Start(key []byte, cfg Config) (int, error) {
	bin, err := FindDaemon()
	if err != nil {
		return 0, err
	}
	keyR, keyW, err := os.Pipe()
	if err != nil {
		return 0, err
	}
	stR, stW, err := os.Pipe()
	if err != nil {
		keyR.Close()
		keyW.Close()
		return 0, err
	}
	devnull, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		return 0, err
	}
	defer devnull.Close()

	cmd := &exec.Cmd{
		Path:        bin,
		Args:        []string{DaemonName},
		Env:         DaemonEnv(),
		Dir:         "/",
		Stdin:       devnull,
		Stdout:      devnull,
		Stderr:      devnull,
		ExtraFiles:  []*os.File{keyR, stW}, // fd 3, fd 4
		SysProcAttr: &syscall.SysProcAttr{Setsid: true},
	}
	err = cmd.Start()
	keyR.Close()
	stW.Close()
	if err != nil {
		keyW.Close()
		stR.Close()
		return 0, fmt.Errorf("starting vaultd: %w", err)
	}

	buf := make([]byte, hex.EncodedLen(len(key))+1)
	hex.Encode(buf, key)
	buf[len(buf)-1] = '\n'
	buf = append(buf, cfg.Line()...)
	_, werr := keyW.Write(buf)
	vcrypto.Zero(buf)
	keyW.Close()

	type result struct {
		line string
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		line, err := bufio.NewReader(stR).ReadString('\n')
		ch <- result{strings.TrimSpace(line), err}
	}()

	var res result
	select {
	case res = <-ch:
	case <-time.After(15 * time.Second):
		cmd.Process.Kill()
		cmd.Wait()
		stR.Close()
		return 0, errors.New("vaultd did not become ready in time")
	}
	stR.Close()

	switch {
	case res.line == "OK":
		pid := cmd.Process.Pid
		cmd.Process.Release()
		return pid, nil
	case strings.HasPrefix(res.line, "ERR "):
		cmd.Wait()
		return 0, errors.New(strings.TrimPrefix(res.line, "ERR "))
	default:
		cmd.Wait()
		if werr != nil {
			return 0, fmt.Errorf("passing key to vaultd: %w", werr)
		}
		return 0, errors.New("vaultd exited unexpectedly")
	}
}
