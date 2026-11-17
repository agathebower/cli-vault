package tests

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	vcrypto "vault-system/pkg/crypto"
	"vault-system/pkg/ipc"
	"vault-system/pkg/keys"
	"vault-system/pkg/server"
	"vault-system/pkg/spawn"
	"vault-system/pkg/vaultfile"
)

// ---------------------------------------------------------------------------
// Test 1: no secret in /proc, ps, env, or on disk
// ---------------------------------------------------------------------------

func TestSecurity1_NoSecretLeakInProc(t *testing.T) {
	const pw = "test123"
	e := newEnv(t)
	// Canary: if the CLI's environment leaked into vaultd we would see it.
	e.extra = []string{"VAULT_MASTERKEY=canary-should-not-propagate", "VAULT_TEST=x"}
	e.initPassword(pw)

	pid := e.pidFromFile()
	pids := pgrepVaultd(t)
	if pid == 0 || !containsInt(pids, pid) {
		t.Fatalf("vaultd not found: pidfile=%d pgrep=%v", pid, pids)
	}
	step(t, "pgrep -x vaultd → %v (pidfile: %d)", pids, pid)

	// Derive the actual AES key so we can search for it too.
	f, err := vaultfile.Load(e.vaultPath())
	if err != nil {
		t.Fatal(err)
	}
	salt, _ := f.Head(vaultfile.SaltSize)
	key := vcrypto.DeriveKey([]byte(pw), salt, vaultfile.PBKDF2Iterations)
	if _, err := f.Open(vaultfile.SaltSize, key); err != nil {
		t.Fatalf("derived key does not open the vault: %v", err)
	}
	keyHex := hex.EncodeToString(key)
	secrets := map[string][]byte{"password": []byte(pw), "key(hex)": []byte(keyHex), "key(raw)": key}
	checkNoSecret := func(what string, data []byte) {
		t.Helper()
		for name, s := range secrets {
			if bytes.Contains(data, s) {
				t.Fatalf("FAIL: %s found in %s", name, what)
			}
		}
		step(t, "%s contains neither password, key (hex) nor key (raw)", what)
	}

	// 1.3 /proc/PID/cmdline
	cmdline, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/cmdline")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("/proc/%d/cmdline = %q", pid, cmdline)
	mustEqual(t, string(cmdline), "vaultd\x00", "cmdline is exactly argv[0]=vaultd")
	checkNoSecret("/proc/PID/cmdline", cmdline)

	comm, _ := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/comm")
	mustEqual(t, strings.TrimSpace(string(comm)), "vaultd", "/proc/PID/comm (PR_SET_NAME)")

	// 1.4 /proc/PID/environ
	environ, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/environ")
	switch {
	case err == nil:
		t.Logf("/proc/%d/environ = %q", pid, environ)
		if bytes.Contains(environ, []byte("VAULT_")) {
			t.Fatalf("FAIL: VAULT_* variable in vaultd environment")
		}
		checkNoSecret("/proc/PID/environ", environ)
	case errors.Is(err, os.ErrPermission):
		step(t, "/proc/%d/environ not readable even by owner (PR_SET_DUMPABLE=0): %v", pid, err)
	default:
		t.Fatal(err)
	}
	// Independent proof of the env filter used when spawning vaultd.
	os.Setenv("VAULT_MASTERKEY", "canary")
	denv := spawn.DaemonEnv()
	os.Unsetenv("VAULT_MASTERKEY")
	for _, kv := range denv {
		if !strings.HasPrefix(kv, "HOME=") && !strings.HasPrefix(kv, "XDG_RUNTIME_DIR=") {
			t.Fatalf("FAIL: daemon env contains %q", kv)
		}
	}
	step(t, "vaultd is spawned with env %v only (no VAULT_*)", denv)

	// 1.5 ps aux
	ps, err := exec.Command("ps", "aux").Output()
	if err != nil {
		t.Fatal(err)
	}
	var lines []string
	for _, l := range strings.Split(string(ps), "\n") {
		if strings.Contains(l, "vaultd") {
			lines = append(lines, l)
		}
	}
	t.Logf("ps aux | grep vaultd:\n%s", strings.Join(lines, "\n"))
	checkNoSecret("ps aux", ps)

	// 1.6 /proc/PID/cwd
	cwd, err := os.Readlink("/proc/" + strconv.Itoa(pid) + "/cwd")
	switch {
	case err == nil:
		mustEqual(t, cwd, "/", "/proc/PID/cwd")
	case errors.Is(err, os.ErrPermission):
		step(t, "/proc/%d/cwd not readable (PR_SET_DUMPABLE=0): %v", pid, err)
	default:
		t.Fatal(err)
	}
	status, _ := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/status")
	for _, l := range strings.Split(string(status), "\n") {
		if strings.HasPrefix(l, "Name:") || strings.HasPrefix(l, "Uid:") {
			t.Logf("/proc/%d/status %s", pid, l)
		}
	}

	// On-disk artefacts.
	vf, _ := os.ReadFile(e.vaultPath())
	checkNoSecret("vault file", vf)
	pf, _ := os.ReadFile(filepath.Join(e.run, "vault.pid"))
	checkNoSecret("vault.pid", pf)
	for _, p := range []string{e.vaultPath(), e.sockPath(), filepath.Join(e.run, "vault.pid")} {
		fi, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o600 {
			t.Fatalf("FAIL: %s has mode %o, want 600", p, fi.Mode().Perm())
		}
		step(t, "%s mode %o", p, fi.Mode().Perm())
	}
}

// ---------------------------------------------------------------------------
// Test 2: SO_PEERCRED
// ---------------------------------------------------------------------------

func TestSecurity2_PeerCred(t *testing.T) {
	uid := os.Getuid()
	dir, err := os.MkdirTemp("", "vp-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	sock := filepath.Join(dir, "s")

	serve := func(allowed int) *net.UnixListener {
		l, err := net.ListenUnix("unix", &net.UnixAddr{Name: sock, Net: "unix"})
		if err != nil {
			t.Fatal(err)
		}
		srv := server.New(make([]byte, 32), filepath.Join(dir, "none"), vaultfile.SaltSize, vaultfile.KeyTypePassword)
		srv.AllowedUID = allowed
		go srv.Serve(l)
		return l
	}
	ping := func() ipc.Response {
		c, err := net.Dial("unix", sock)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		json.NewEncoder(c).Encode(ipc.Request{Op: "ping"})
		var r ipc.Response
		if err := json.NewDecoder(c).Decode(&r); err != nil {
			t.Fatal(err)
		}
		return r
	}

	// Real kernel SO_PEERCRED: our UID is reported, foreign UID is rejected.
	l := serve(uid + 4242) // daemon pretends to belong to another user
	r := ping()
	l.Close()
	if r.OK || r.Error != "permission denied" {
		t.Fatalf("FAIL: peer with uid %d accepted by daemon for uid %d: %+v", uid, uid+4242, r)
	}
	step(t, "peer uid %d ≠ allowed uid %d → %q", uid, uid+4242, r.Error)

	l = serve(uid)
	r = ping()
	l.Close()
	if !r.OK || r.PID != os.Getpid() {
		t.Fatalf("FAIL: same-uid peer rejected: %+v", r)
	}
	step(t, "peer uid %d = allowed uid → ok", uid)

	// Running daemon: socket 0600, runtime dir 0700, same user works.
	e := newEnv(t)
	e.initPassword("pc")
	fi, _ := os.Stat(e.sockPath())
	if fi.Mode().Perm() != 0o600 || fi.Mode()&os.ModeSocket == 0 {
		t.Fatalf("FAIL: socket mode %v", fi.Mode())
	}
	step(t, "%s is a socket with mode %o", e.sockPath(), fi.Mode().Perm())
	mustOK(t, e.vault("", "add", "k", "v"), "same-user add")
	step(t, "same-user client accepted")

	// Practical cross-user check, only if passwordless sudo is available.
	if exec.Command("sudo", "-n", "-u", "nobody", "true").Run() != nil {
		t.Log("cross-user check skipped: no passwordless sudo (kernel-level SO_PEERCRED rejection proven above)")
		return
	}
	os.Chmod(e.run, 0o711)
	os.Chmod(e.sockPath(), 0o666) // even if file permissions were too open...
	out, _ := exec.Command("sudo", "-n", "-u", "nobody", "python3", "-c",
		`import socket,sys;s=socket.socket(socket.AF_UNIX);s.connect(sys.argv[1]);s.sendall(b'{"op":"get","key":"k"}\n');print(s.recv(4096).decode())`,
		e.sockPath()).CombinedOutput()
	os.Chmod(e.run, 0o700)
	os.Chmod(e.sockPath(), 0o600)
	if !strings.Contains(string(out), "permission denied") {
		t.Fatalf("FAIL: user nobody got: %s", out)
	}
	step(t, "user nobody → %s", strings.TrimSpace(string(out)))
}

// ---------------------------------------------------------------------------
// Test 3: symmetric roundtrip
// ---------------------------------------------------------------------------

func TestSecurity3_SymmetricRoundtrip(t *testing.T) {
	const pw = "correct horse"
	e := newEnv(t)
	r := e.initPassword(pw)
	if !strings.Contains(r.stdout, "SYMMETRISCHER") {
		t.Fatalf("FAIL: missing SYMMETRISCHER:\n%s", r)
	}
	step(t, "1. init output: %q", strings.Split(r.stdout, "\n")[0])

	mustOK(t, e.vault("", "add", "github_token", "ghp_testtoken_12345"), "add")
	step(t, "2. add github_token")
	mustEqual(t, e.vault("", "get", "github_token").stdout, "ghp_testtoken_12345", "3. get github_token")

	mustOK(t, e.vault("", "stop"), "stop")
	step(t, "4. stop")
	r = e.vaultTTY([]string{pw}, "daemon", "start", "--password")
	mustOK(t, r, "daemon start --password")
	step(t, "5. daemon start --password: %s", strings.TrimSpace(r.stdout))
	mustEqual(t, e.vault("", "get", "github_token").stdout, "ghp_testtoken_12345", "6. get after restart")

	mustFail(t, e.vault("", "get", "nonexistent_key"), "not found", "7. get nonexistent_key")
	step(t, "7. nonexistent_key → not found")
}

// ---------------------------------------------------------------------------
// Test 4: asymmetric roundtrip (RSA)
// ---------------------------------------------------------------------------

func TestSecurity4_AsymmetricRoundtripRSA(t *testing.T) {
	key := sshKeygen(t, "rsa", "2048", "")
	step(t, "1. ssh-keygen -t rsa -b 2048 -N \"\" → %s", key)
	asymRoundtrip(t, key, "", vaultfile.KeyTypeRSA)
}

func asymRoundtrip(t *testing.T, key, pass, wantType string) {
	t.Helper()
	e := newEnv(t)
	var in []string
	if pass != "" {
		in = []string{pass}
	}
	r := e.vaultTTY(in, "init", "--key", key)
	mustOK(t, r, "init --key")
	if !strings.Contains(r.stdout, "ASYMMETRISCHER") {
		t.Fatalf("FAIL: missing ASYMMETRISCHER:\n%s", r)
	}
	step(t, "2. init output: %q", strings.Split(r.stdout, "\n")[0])

	mustOK(t, e.vault("", "add", "test_cred", "secret_asymmetric"), "add")
	step(t, "3. add test_cred")
	mustEqual(t, e.vault("", "get", "test_cred").stdout, "secret_asymmetric", "4. get test_cred")
	mustOK(t, e.vault("", "stop"), "stop")
	step(t, "5. stop")
	r = e.vaultTTY(in, "daemon", "start", "--key", key)
	mustOK(t, r, "daemon start --key")
	step(t, "6. daemon start --key: %s", strings.TrimSpace(r.stdout))
	mustEqual(t, e.vault("", "get", "test_cred").stdout, "secret_asymmetric", "7. get after restart")

	if st := e.vault("", "status").stdout; !strings.Contains(st, "keytype: "+wantType) {
		t.Fatalf("FAIL: status %q does not report keytype %s", st, wantType)
	}
	step(t, "8. status reports keytype %s", wantType)
	raw, _ := os.ReadFile(e.vaultPath())
	pub, _ := os.ReadFile(key + ".pub")
	pubB64 := strings.Fields(string(pub))[1]
	for _, s := range []string{"PRIVATE KEY", "ssh-", wantType, pubB64[20:40]} {
		if bytes.Contains(raw, []byte(s)) {
			t.Fatalf("FAIL: %q found in vault file", s)
		}
	}
	step(t, "9. vault file contains neither key type nor public key")
}

func TestExtra_AsymmetricEd25519(t *testing.T) {
	asymRoundtrip(t, sshKeygen(t, "ed25519", "", ""), "", vaultfile.KeyTypeEd25519)
}

func TestExtra_AsymmetricECDSA(t *testing.T) {
	asymRoundtrip(t, sshKeygen(t, "ecdsa", "256", ""), "", vaultfile.KeyTypeECDSA)
}

func TestExtra_AsymmetricEncryptedKeyCorrectPassphrase(t *testing.T) {
	asymRoundtrip(t, sshKeygen(t, "ed25519", "", "mypassphrase"), "mypassphrase", vaultfile.KeyTypeEd25519)
}

// ---------------------------------------------------------------------------
// Test 5: wrong password
// ---------------------------------------------------------------------------

func TestSecurity5_WrongPassword(t *testing.T) {
	e := newEnv(t)
	e.initPassword("correct")
	step(t, "1. init --password (correct)")
	mustOK(t, e.vault("", "stop"), "stop")
	step(t, "2. stop")

	r := e.vaultTTY([]string{"wrong"}, "daemon", "start", "--password")
	mustFail(t, r, "failed to decrypt vault", "3./4. daemon start with wrong password")
	step(t, "4. error: %s", strings.TrimSpace(r.stderr))

	r = e.vault("", "status")
	mustEqual(t, strings.TrimSpace(r.stdout), "not running", "5. status")
	if pids := pgrepVaultd(t); e.pidFromFile() != 0 && containsInt(pids, e.pidFromFile()) {
		t.Fatal("FAIL: a vaultd is running")
	}
}

// ---------------------------------------------------------------------------
// Test 6: process discovery
// ---------------------------------------------------------------------------

func TestSecurity6_ProcessDiscovery(t *testing.T) {
	e := newEnv(t)
	e.initPassword("disc")
	pid := e.pidFromFile()
	if !containsInt(pgrepVaultd(t), pid) {
		t.Fatalf("FAIL: pgrep vaultd does not list %d", pid)
	}
	step(t, "2. pgrep vaultd → %v", pgrepVaultd(t))

	time.Sleep(1100 * time.Millisecond)
	r := e.vault("", "status")
	mustOK(t, r, "status")
	want := "running (PID: " + strconv.Itoa(pid) + ", uptime: "
	if !strings.HasPrefix(r.stdout, want) {
		t.Fatalf("FAIL: status = %q, want prefix %q", r.stdout, want)
	}
	step(t, "3. status → %s", strings.TrimSpace(r.stdout))

	r = e.vault("", "stop")
	mustOK(t, r, "stop")
	step(t, "4. stop → %s", strings.TrimSpace(r.stdout))

	r = e.vault("", "status")
	mustEqual(t, strings.TrimSpace(r.stdout), "not running", "5. status")
	if containsInt(pgrepVaultd(t), pid) {
		t.Fatalf("FAIL: pid %d still running", pid)
	}
	step(t, "6. pgrep vaultd no longer lists %d (all: %v)", pid, pgrepVaultd(t))
	if _, err := os.Stat(e.sockPath()); !os.IsNotExist(err) {
		t.Fatal("FAIL: socket not removed")
	}
	if _, err := os.Stat(filepath.Join(e.run, "vault.pid")); !os.IsNotExist(err) {
		t.Fatal("FAIL: pid file not removed")
	}
	step(t, "socket and pid file removed on SIGTERM")
}

// ---------------------------------------------------------------------------
// Test 7: wrong passphrase for SSH key
// ---------------------------------------------------------------------------

func TestSecurity7_WrongKeyPassphrase(t *testing.T) {
	key := sshKeygen(t, "rsa", "2048", "mypassphrase")
	step(t, "1. ssh-keygen -t rsa -N mypassphrase")
	e := newEnv(t)
	r := e.vaultTTY([]string{"wrongpassphrase"}, "init", "--key", key)
	mustFail(t, r, "failed to decrypt private key", "2./3. init --key with wrong passphrase")
	step(t, "3. error: %s", strings.TrimSpace(r.stderr))
	if _, err := os.Stat(e.vaultPath()); !os.IsNotExist(err) {
		t.Fatal("FAIL: vault file created despite error")
	}
	mustEqual(t, strings.TrimSpace(e.vault("", "status").stdout), "not running", "no daemon started")
}

// ---------------------------------------------------------------------------
// Test 8: multiple add/get
// ---------------------------------------------------------------------------

func TestSecurity8_MultipleOps(t *testing.T) {
	const pw = "multi"
	sshVal := "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\n-----END PRIVATE KEY-----"
	e := newEnv(t)
	e.initPassword(pw)
	vals := map[string]string{"db_pass": "dbpass123", "api_key": "key_xyz", "ssh_key": sshVal}
	for k, v := range vals {
		mustOK(t, e.vault("", "add", k, v), "add "+k)
	}
	step(t, "2. added db_pass, api_key, ssh_key")
	for k, v := range vals {
		mustEqual(t, e.vault("", "get", k).stdout, v, "3. get "+k)
	}
	mustOK(t, e.vault("", "add", "db_pass", "updated_password"), "update")
	vals["db_pass"] = "updated_password"
	mustEqual(t, e.vault("", "get", "db_pass").stdout, "updated_password", "5. get db_pass after update")
	mustOK(t, e.vault("", "stop"), "stop")
	mustOK(t, e.vaultTTY([]string{pw}, "daemon", "start", "--password"), "daemon start")
	step(t, "6./7. stop + daemon start --password")
	for k, v := range vals {
		mustEqual(t, e.vault("", "get", k).stdout, v, "8. after restart "+k)
	}
	mustEqual(t, e.vault("", "list").stdout, "api_key\ndb_pass\nssh_key\n", "list")
}

// ---------------------------------------------------------------------------
// Extras
// ---------------------------------------------------------------------------

func TestExtra_InitRefusesExistingVault(t *testing.T) {
	e := newEnv(t)
	e.initPassword("a")
	mustOK(t, e.vault("", "add", "k", "v"), "add")
	mustFail(t, e.vaultTTY([]string{"b", "b"}, "init", "--password"), "already exists", "re-init without --force")
	mustFail(t, e.vaultTTY([]string{"b", "b"}, "init", "--password", "--force"), "vaultd is running", "--force while running")
	mustOK(t, e.vault("", "stop"), "stop")
	r := e.vaultTTY([]string{"b", "b"}, "init", "--password", "--force")
	mustOK(t, r, "init --force")
	if !strings.Contains(r.stdout, "Previous vault moved to "+e.vaultPath()+".") {
		t.Fatalf("FAIL: no backup reported:\n%s", r)
	}
	mustFail(t, e.vault("", "get", "k"), "not found", "new vault is empty")
	matches, _ := filepath.Glob(e.vaultPath() + ".*")
	if len(matches) != 1 {
		t.Fatalf("FAIL: backups %v", matches)
	}
	step(t, "backup kept at %s", matches[0])
}

func TestExtra_InitPasswordMismatchAndNoTTY(t *testing.T) {
	e := newEnv(t)
	mustFail(t, e.vaultTTY([]string{"one", "two"}, "init", "--password"), "do not match", "confirmation mismatch")
	mustFail(t, e.vault("test123\ntest123\n", "init", "--password"), "no terminal", "password via stdin refused")
	if _, err := os.Stat(e.vaultPath()); !os.IsNotExist(err) {
		t.Fatal("FAIL: vault file created")
	}
}

func TestExtra_WrongKeyForVault(t *testing.T) {
	k1 := sshKeygen(t, "ed25519", "", "")
	k2 := sshKeygen(t, "ed25519", "", "")
	e := newEnv(t)
	mustOK(t, e.vaultTTY(nil, "init", "--key", k1), "init k1")
	mustOK(t, e.vault("", "stop"), "stop")
	mustFail(t, e.vaultTTY(nil, "daemon", "start", "--key", k2), "failed to decrypt vault", "daemon start with other key")
	mustFail(t, e.vaultTTY([]string{"x"}, "daemon", "start", "--password"), "failed to decrypt vault", "password on key vault")
	mustFail(t, e.vaultTTY([]string{"x"}, "daemon", "start"), "--key PATH", "key vault without --key: hint")
	rsa := sshKeygen(t, "rsa", "2048", "")
	mustFail(t, e.vaultTTY(nil, "daemon", "start", "--key", rsa), "failed to decrypt vault", "RSA key on ed25519 vault")

	e2 := newEnv(t)
	e2.initPassword("pw")
	mustOK(t, e2.vault("", "stop"), "stop")
	mustFail(t, e2.vaultTTY(nil, "daemon", "start", "--key", k1), "failed to decrypt vault", "key on password vault")
	mustFail(t, e2.vaultTTY(nil, "daemon", "start", "--key", rsa), "failed to decrypt vault", "RSA key on password vault")
}

func TestExtra_TamperedHeaderRejected(t *testing.T) {
	e := newEnv(t)
	e.initPassword("tamper")
	mustOK(t, e.vault("", "stop"), "stop")
	raw, _ := os.ReadFile(e.vaultPath())
	for _, pos := range []int{0, vaultfile.SaltSize + 3, len(raw) - 1} { // salt, nonce, tag
		mod := bytes.Clone(raw)
		mod[pos] ^= 1
		os.WriteFile(e.vaultPath(), mod, 0o600)
		mustFail(t, e.vaultTTY([]string{"tamper"}, "daemon", "start", "--password"), "failed to decrypt vault", fmt.Sprintf("byte %d flipped", pos))
	}
	os.WriteFile(e.vaultPath(), raw, 0o600)
	mustOK(t, e.vaultTTY([]string{"tamper"}, "daemon", "start", "--password"), "original file still opens")
}

func TestExtra_AddFromStdinAndPrompt(t *testing.T) {
	e := newEnv(t)
	e.initPassword("stdin")
	multi := "line1\nline2\n"
	mustOK(t, e.vault(multi, "add", "multi"), "add from stdin")
	mustEqual(t, e.vault("", "get", "multi").stdout, "line1\nline2", "multi-line value (one trailing newline stripped)")
	mustOK(t, e.vaultTTY([]string{"typed-secret"}, "add", "typed"), "add via hidden prompt")
	mustEqual(t, e.vault("", "get", "typed").stdout, "typed-secret", "typed value")
	mustOK(t, e.vault("", "rm", "typed"), "rm")
	mustFail(t, e.vault("", "get", "typed"), "not found", "get after rm")
	mustFail(t, e.vault("", "add", "a", "b", "c"), "usage", "too many args")
}

func TestExtra_NotRunningAndManualVaultd(t *testing.T) {
	e := newEnv(t)
	mustFail(t, e.vault("", "get", "x"), "vaultd not running", "get without daemon")
	cmd := exec.Command(filepath.Join(binDir, "vaultd"))
	cmd.Env = e.environ()
	out, err := cmd.CombinedOutput()
	if exitCode(err) != 2 || !strings.Contains(string(out), "must be started by") {
		t.Fatalf("FAIL: manual vaultd: %v %s", err, out)
	}
	step(t, "vaultd without key pipe refuses to run: %s", strings.TrimSpace(string(out)))
	mustFail(t, e.vaultTTY([]string{"x"}, "daemon", "start", "--password"), "no vault found", "daemon start without vault")
}

func TestExtra_StopIgnoresForeignPID(t *testing.T) {
	e := newEnv(t)
	// Stale pid file pointing at a process that is not vaultd (ourselves).
	os.WriteFile(filepath.Join(e.run, "vault.pid"), []byte(strconv.Itoa(os.Getpid())), 0o600)
	r := e.vault("", "stop")
	mustOK(t, r, "stop with stale pid")
	if !strings.Contains(r.stdout, "stale") {
		t.Fatalf("FAIL: %s", r)
	}
	if err := syscall.Kill(os.Getpid(), 0); err != nil {
		t.Fatal("we got killed?!")
	}
	step(t, "stale pid file not pointing at vaultd → no signal sent")
}

// ---------------------------------------------------------------------------
// Opaque vault file
// ---------------------------------------------------------------------------

func TestExtra_OpaqueVaultFile(t *testing.T) {
	e := newEnv(t)
	r := e.initPassword("opaque")
	p := e.vaultPath()
	base := filepath.Base(p)
	if strings.Contains(strings.ToLower(base), "vault") || len(base) != 17 {
		t.Fatalf("FAIL: vault file name %q is not opaque", base)
	}
	if !strings.Contains(r.stdout, p) {
		t.Fatalf("FAIL: init does not report %s:\n%s", p, r)
	}
	if _, err := os.Stat(e.legacyPath()); !os.IsNotExist(err) {
		t.Fatal("FAIL: ~/.vault created")
	}
	mustEqual(t, strings.TrimSpace(e.vault("", "path").stdout), p, "vault path")
	mustOK(t, e.vault("", "add", "user_github", "x"), "add")
	raw, _ := os.ReadFile(p)
	for _, s := range []string{"VAUT", "password", "keytype", "salt", "pbkdf2", "created_at", "credentials", "user_github"} {
		if bytes.Contains(raw, []byte(s)) {
			t.Fatalf("FAIL: %q readable in vault file", s)
		}
	}
	printable := 0
	for _, b := range raw {
		if b >= 0x20 && b < 0x7f {
			printable++
		}
	}
	// Random bytes: ~37% printable. JSON or text would be ~100%.
	if frac := float64(printable) / float64(len(raw)); frac > 0.6 {
		t.Fatalf("FAIL: %.0f%% of the file is printable ASCII", frac*100)
	}
	step(t, "%s (%d bytes): no magic, no field names, no keytype; same name for the same HOME/uid", base, len(raw))
}

// ---------------------------------------------------------------------------
// Automatic shutdown
// ---------------------------------------------------------------------------

func (e *env) waitStopped(t *testing.T, within time.Duration) time.Duration {
	t.Helper()
	start := time.Now()
	for time.Since(start) < within {
		if strings.TrimSpace(e.vault("", "status").stdout) == "not running" {
			return time.Since(start)
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("FAIL: vaultd still running after %s", within)
	return 0
}

func (e *env) assertCleanedUp(t *testing.T, pid int) {
	t.Helper()
	time.Sleep(100 * time.Millisecond)
	if containsInt(pgrepVaultd(t), pid) {
		t.Fatalf("FAIL: pid %d still running", pid)
	}
	for _, p := range []string{e.sockPath(), filepath.Join(e.run, "vault.pid")} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Fatalf("FAIL: %s not removed", p)
		}
	}
}

func TestExtra_IdleTimeout(t *testing.T) {
	e := newEnv(t)
	r := e.vaultTTY([]string{"idle", "idle"}, "init", "--password", "--idle", "2s", "--ttl", "0")
	mustOK(t, r, "init --idle 2s --ttl 0")
	if !strings.Contains(r.stdout, "auto-stop: idle 2s, max never") {
		t.Fatalf("FAIL: %s", r)
	}
	pid := e.pidFromFile()
	mustOK(t, e.vault("", "add", "k", "v"), "add")
	// Requests keep it alive well past the idle timeout ...
	for i := 0; i < 5; i++ {
		time.Sleep(800 * time.Millisecond)
		mustEqual(t, e.vault("", "get", "k").stdout, "v", "get keeps daemon alive")
	}
	st := e.vault("", "status").stdout
	if !strings.Contains(st, "auto-stop in ") || !strings.Contains(st, "(idle 2s, max never)") {
		t.Fatalf("FAIL: status %q", st)
	}
	step(t, "alive after 4s of activity with --idle 2s; status: %s", strings.TrimSpace(st))
	// ... status pings don't (waitStopped polls status).
	took := e.waitStopped(t, 5*time.Second)
	e.assertCleanedUp(t, pid)
	step(t, "stopped %s after the last request; socket and pid file removed", took.Round(100*time.Millisecond))
	mustFail(t, e.vault("", "get", "k"), "vaultd not running", "get after idle stop")
}

func TestExtra_MaxLifetime(t *testing.T) {
	e := newEnv(t)
	e.initPassword("ttl")
	mustOK(t, e.vault("", "stop"), "stop")
	r := e.vaultTTY([]string{"ttl"}, "daemon", "start", "--idle", "0", "--ttl", "3s")
	mustOK(t, r, "daemon start --ttl 3s")
	pid := e.pidFromFile()
	start := time.Now()
	// Constant activity does not extend the max lifetime.
	for time.Since(start) < 2500*time.Millisecond {
		mustOK(t, e.vault("", "list"), "list")
		time.Sleep(300 * time.Millisecond)
	}
	e.waitStopped(t, 3*time.Second)
	e.assertCleanedUp(t, pid)
	step(t, "stopped after %s despite activity (--ttl 3s)", time.Since(start).Round(100*time.Millisecond))
}

func TestExtra_TimeoutDefaultsAndValidation(t *testing.T) {
	e := newEnv(t)
	e.initPassword("def")
	st := e.vault("", "status").stdout
	if !strings.Contains(st, "(idle 30m, max 8h)") {
		t.Fatalf("FAIL: default timeouts: %q", st)
	}
	step(t, "defaults: %s", strings.TrimSpace(st))
	mustOK(t, e.vault("", "stop"), "stop")
	mustOK(t, e.vaultTTY([]string{"def"}, "daemon", "start", "--idle", "0", "--ttl", "0"), "no timeouts")
	if st := e.vault("", "status").stdout; !strings.Contains(st, "auto-stop: never") {
		t.Fatalf("FAIL: %q", st)
	}
	mustOK(t, e.vault("", "stop"), "stop")
	mustFail(t, e.vaultTTY([]string{"def"}, "daemon", "start", "--idle", "-1s"), "negative", "negative idle")
	mustFail(t, e.vaultTTY([]string{"def"}, "daemon", "start", "--ttl", "5ms"), "at least 1s", "tiny ttl")
	mustFail(t, e.vaultTTY([]string{"def"}, "daemon", "start", "--ttl", "abc"), "usage", "bad duration")
}

// ---------------------------------------------------------------------------
// Migration of the old ~/.vault format
// ---------------------------------------------------------------------------

// writeLegacy writes a v1 vault ("VAUT" + plaintext JSON header) to ~/.vault.
func (e *env) writeLegacy(t *testing.T, header map[string]any, key []byte, creds map[string]string) {
	t.Helper()
	hj, _ := json.Marshal(header)
	prefix := []byte("VAUT\x01")
	prefix = binary.BigEndian.AppendUint16(prefix, uint16(len(hj)))
	prefix = append(append(prefix, hj...), '\n')
	pt, _ := json.Marshal(map[string]any{"credentials": creds})
	ct, err := vcrypto.Encrypt(key, pt, prefix)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(e.legacyPath(), append(prefix, ct...), 0o600); err != nil {
		t.Fatal(err)
	}
}

func (e *env) checkMigrated(t *testing.T, r result, creds map[string]string) {
	t.Helper()
	mustOK(t, r, "daemon start (migration)")
	if !strings.Contains(r.stdout, "Migrated") {
		t.Fatalf("FAIL: no migration message:\n%s", r)
	}
	if _, err := os.Stat(e.legacyPath()); !os.IsNotExist(err) {
		t.Fatal("FAIL: ~/.vault not removed")
	}
	raw, _ := os.ReadFile(e.vaultPath())
	if bytes.Contains(raw, []byte("VAUT")) || bytes.Contains(raw, []byte("keytype")) {
		t.Fatal("FAIL: migrated file still in old format")
	}
	for k, v := range creds {
		mustEqual(t, e.vault("", "get", k).stdout, v, "get "+k+" after migration")
	}
	step(t, "~/.vault migrated to %s, old file removed, %d credentials intact", filepath.Base(e.vaultPath()), len(creds))
}

func TestExtra_MigrateLegacyPassword(t *testing.T) {
	e := newEnv(t)
	salt := []byte("0123456789abcdef")
	key := vcrypto.DeriveKey([]byte("legacy"), salt, 100000)
	creds := map[string]string{"github_token": "ghp_x", "db": "p@ss"}
	e.writeLegacy(t, map[string]any{"keytype": "password", "salt": hex.EncodeToString(salt),
		"pbkdf2_iterations": 100000, "created_at": 1}, key, creds)

	mustFail(t, e.vaultTTY([]string{"wrong"}, "daemon", "start"), "failed to decrypt vault", "wrong password")
	if _, err := os.Stat(e.legacyPath()); err != nil {
		t.Fatal("FAIL: ~/.vault touched after failed unlock")
	}
	if _, err := os.Stat(e.vaultPath()); !os.IsNotExist(err) {
		t.Fatal("FAIL: new vault written after failed unlock")
	}
	mustFail(t, e.vaultTTY([]string{"legacy", "legacy"}, "init", "--password"), "already exists", "init refuses with legacy vault")
	e.checkMigrated(t, e.vaultTTY([]string{"legacy"}, "daemon", "start"), creds)
	mustOK(t, e.vault("", "stop"), "stop")
	mustOK(t, e.vaultTTY([]string{"legacy"}, "daemon", "start"), "restart with new format")
	mustEqual(t, e.vault("", "get", "db").stdout, "p@ss", "get after restart")
}

func TestExtra_MigrateLegacyRSA(t *testing.T) {
	e := newEnv(t)
	kp := sshKeygen(t, "rsa", "2048", "")
	priv, err := keys.Load(kp, nil)
	if err != nil {
		t.Fatal(err)
	}
	key, _ := vcrypto.Random(32)
	wrapped, _ := rsa.EncryptOAEP(sha256.New(), rand.Reader, &priv.(*rsa.PrivateKey).PublicKey, key, nil)
	creds := map[string]string{"api": "secret"}
	e.writeLegacy(t, map[string]any{"keytype": "ssh-rsa", "public_key": "x",
		"wrapped_key": base64.StdEncoding.EncodeToString(wrapped), "created_at": 1}, key, creds)
	mustFail(t, e.vaultTTY([]string{"x"}, "daemon", "start"), "--key PATH", "legacy key vault without --key")
	e.checkMigrated(t, e.vaultTTY(nil, "daemon", "start", "--key", kp), creds)
	mustOK(t, e.vault("", "stop"), "stop")
	mustOK(t, e.vaultTTY(nil, "daemon", "start", "--key", kp), "restart with new format")
	mustEqual(t, e.vault("", "get", "api").stdout, "secret", "get after restart")
}
