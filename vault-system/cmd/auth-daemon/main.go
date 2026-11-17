// vaultd is the vault agent. It is started by `vault init` / `vault daemon
// start`, receives the vault key once via fd 3, keeps it in memory and
// serves requests on $XDG_RUNTIME_DIR/vault.sock. The key never leaves the
// process. It exits on SIGTERM/SIGINT or when its idle / max lifetime
// expires.
package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	vcrypto "vault-system/pkg/crypto"
	"vault-system/pkg/ipc"
	"vault-system/pkg/server"
	"vault-system/pkg/spawn"
	"vault-system/pkg/vaultfile"
)

func prctl(option int, arg2 uintptr) error {
	_, _, e := syscall.RawSyscall(syscall.SYS_PRCTL, uintptr(option), arg2, 0)
	if e != 0 {
		return e
	}
	return nil
}

func main() {
	// 1. Read the key from fd 3 before anything else, then close it.
	keyPipe := os.NewFile(3, "key-pipe")
	status := os.NewFile(4, "status-pipe")
	var st syscall.Stat_t
	if syscall.Fstat(3, &st) != nil || syscall.Fstat(4, &st) != nil {
		fmt.Fprintln(os.Stderr, "vaultd: must be started by 'vault init' or 'vault daemon start'")
		os.Exit(2)
	}
	raw, err := io.ReadAll(io.LimitReader(keyPipe, 512))
	keyPipe.Close()

	fail := func(format string, a ...any) {
		fmt.Fprintf(status, "ERR "+format+"\n", a...)
		status.Close()
		os.Exit(1)
	}
	if err != nil {
		fail("reading key pipe: %v", err)
	}
	hexKey, cfgLine, _ := bytes.Cut(raw, []byte("\n"))
	cfg, cerr := spawn.ParseConfig(string(cfgLine)) // before raw is zeroed
	key := make([]byte, hex.DecodedLen(len(hexKey)))
	_, derr := hex.Decode(key, hexKey)
	vcrypto.Zero(raw)
	if derr != nil || len(key) != vcrypto.KeySize {
		fail("invalid key received on fd 3")
	}
	if cerr != nil {
		fail("%v", cerr)
	}
	syscall.Mlock(key) // best effort: keep key out of swap

	// 2. Process hardening: name "vaultd", not dumpable (no ptrace / core
	//    dumps / /proc/PID/mem by other processes of the same user).
	name := []byte("vaultd\x00")
	prctl(syscall.PR_SET_NAME, uintptr(unsafe.Pointer(&name[0])))
	prctl(syscall.PR_SET_DUMPABLE, 0)
	syscall.Umask(0o077)
	os.Chdir("/")

	// 3. Verify the key against the vault.
	vaultPath, err := vaultfile.DefaultPath()
	if err != nil {
		fail("%v", err)
	}
	srv := server.New(key, vaultPath, cfg.HeadLen, cfg.KeyType)
	srv.IdleTimeout, srv.MaxLifetime = cfg.IdleTimeout, cfg.MaxLifetime
	if err := srv.Verify(); err != nil {
		vcrypto.Zero(key)
		fail("%v", err)
	}

	// 4. Socket + PID file.
	sockPath, err := ipc.SocketPath()
	if err != nil {
		fail("%v", err)
	}
	pidPath, _ := ipc.PIDPath()
	if c, err := net.DialTimeout("unix", sockPath, time.Second); err == nil {
		c.Close()
		fail("vaultd is already running (%s)", sockPath)
	}
	os.Remove(sockPath) // stale socket from a crashed daemon

	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: sockPath, Net: "unix"})
	if err != nil {
		fail("listen %s: %v", sockPath, err)
	}
	os.Chmod(sockPath, 0o600)
	l.SetUnlinkOnClose(true)

	myPID := strconv.Itoa(os.Getpid())
	if err := vaultfile.WriteAtomic(pidPath, []byte(myPID+"\n")); err != nil {
		l.Close()
		fail("writing pid file: %v", err)
	}

	// 5. Shutdown on SIGTERM/SIGINT; ignore SIGHUP.
	signal.Ignore(syscall.SIGHUP, syscall.SIGPIPE)
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-sigs
		l.Close()
	}()
	// Automatic shutdown after idle timeout / max lifetime.
	go func() {
		srv.WaitExpired()
		l.Close()
	}()

	fmt.Fprint(status, "OK\n")
	status.Close()

	srv.Serve(l)

	// Cleanup: socket is unlinked by l.Close(); remove pid file if it is ours.
	if b, err := os.ReadFile(pidPath); err == nil && strings.TrimSpace(string(b)) == myPID {
		os.Remove(pidPath)
	}
	srv.Wipe()
	os.Exit(0)
}
