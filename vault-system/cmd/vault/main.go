// vault is the CLI. It never stores the vault key itself: `init` and
// `daemon start` derive/unwrap the key, verify it, hand it to vaultd via a
// pipe and forget it. All other commands talk to vaultd over its socket.
package main

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	vcrypto "vault-system/pkg/crypto"
	"vault-system/pkg/ipc"
	"vault-system/pkg/keys"
	"vault-system/pkg/server"
	"vault-system/pkg/spawn"
	"vault-system/pkg/tty"
	"vault-system/pkg/vaultfile"
)

const usage = `Usage:
  vault init --password [--force]        Create the vault (AES-256-GCM, PBKDF2) and start vaultd
  vault init --key PATH [--force]        Create the vault protected by an SSH key (RSA / Ed25519 / ECDSA P-256)
  vault daemon start [--password | --key PATH]
                                         Start vaultd for an existing vault (e.g. after reboot)
      init / daemon start also take:
      --idle DUR                         stop vaultd after DUR without a request (default 30m, 0 = never)
      --ttl DUR                          stop vaultd DUR after start in any case   (default 8h,  0 = never)
  vault add KEY [VALUE]                  Store a credential. Without VALUE: hidden prompt,
                                         or read from stdin if piped (one trailing newline stripped)
  vault get KEY                          Print a credential
  vault list                             List credential names
  vault rm KEY                           Delete a credential
  vault status                           Show whether vaultd is running and when it stops
  vault path                             Print the location of the vault file (for backups)
  vault stop                             Stop vaultd (SIGTERM)

Secrets (password, passphrase) are only ever read from /dev/tty.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	var err error
	args := os.Args[2:]
	switch os.Args[1] {
	case "init":
		err = cmdInit(args)
	case "daemon":
		if len(args) < 1 || args[0] != "start" {
			err = usageErr("usage: vault daemon start [--password | --key PATH] [--idle DUR] [--ttl DUR]")
		} else {
			err = cmdDaemonStart(args[1:])
		}
	case "add":
		err = cmdAdd(args)
	case "get":
		err = cmdGet(args)
	case "list", "ls":
		err = cmdList(args)
	case "rm", "delete":
		err = cmdRm(args)
	case "status":
		err = cmdStatus()
	case "stop":
		err = cmdStop()
	case "path":
		err = cmdPath()
	case "help", "-h", "--help":
		fmt.Print(usage)
	default:
		err = usageErr(fmt.Sprintf("unknown command %q\n\n%s", os.Args[1], usage))
	}
	if err != nil {
		var ue usageError
		fmt.Fprintln(os.Stderr, "error:", err)
		if errors.As(err, &ue) {
			os.Exit(2)
		}
		os.Exit(1)
	}
}

type usageError struct{ msg string }

func (u usageError) Error() string { return u.msg }
func usageErr(msg string) error    { return usageError{msg} }

// ---------------------------------------------------------------- init

// Default automatic shutdown of vaultd.
const (
	DefaultIdleTimeout = 30 * time.Minute
	DefaultMaxLifetime = 8 * time.Hour
)

// timeoutFlags registers --idle and --ttl on fs.
func timeoutFlags(fs *flag.FlagSet) func() (time.Duration, time.Duration, error) {
	idle := fs.Duration("idle", DefaultIdleTimeout, "stop vaultd after this long without a request (0 = never)")
	ttl := fs.Duration("ttl", DefaultMaxLifetime, "stop vaultd this long after start, regardless of use (0 = never)")
	return func() (time.Duration, time.Duration, error) {
		if *idle < 0 || *ttl < 0 {
			return 0, 0, usageErr("--idle and --ttl must not be negative")
		}
		if (*idle != 0 && *idle < time.Second) || (*ttl != 0 && *ttl < time.Second) {
			return 0, 0, usageErr("--idle and --ttl must be at least 1s (or 0 = never)")
		}
		return *idle, *ttl, nil
	}
}

func cmdInit(args []string) error {
	const use = "usage: vault init --password | --key PATH [--force] [--idle DUR] [--ttl DUR]"
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	usePw := fs.Bool("password", false, "protect the vault with a password")
	keyPath := fs.String("key", "", "protect the vault with this SSH private key")
	force := fs.Bool("force", false, "replace an existing vault (the old file is kept as a backup)")
	timeouts := timeoutFlags(fs)
	if err := fs.Parse(args); err != nil {
		return usageErr(use)
	}
	if *usePw == (*keyPath != "") || fs.NArg() > 0 {
		return usageErr(use)
	}
	idle, ttl, err := timeouts()
	if err != nil {
		return err
	}

	vaultPath, err := vaultfile.DefaultPath()
	if err != nil {
		return err
	}
	legacyPath, err := vaultfile.LegacyPath()
	if err != nil {
		return err
	}
	var existing []string
	for _, p := range []string{vaultPath, legacyPath} {
		if vaultfile.Exists(p) {
			existing = append(existing, p)
		}
	}
	if len(existing) > 0 && !*force {
		return fmt.Errorf("vault already exists at %s (use 'vault daemon start' to unlock it, or 'vault init --force' to replace it)", existing[0])
	}
	if resp, err := ipc.Call(ipc.Request{Op: "ping"}); err == nil && resp.OK {
		return fmt.Errorf("vaultd is running (PID: %d); run 'vault stop' first", resp.PID)
	}

	cfg := spawn.Config{IdleTimeout: idle, MaxLifetime: ttl}
	var key, head []byte
	if *usePw {
		fmt.Println("Initialisiere Vault mit SYMMETRISCHER Verschlüsselung (AES-256-GCM, PBKDF2)...")
		pw, err := tty.ReadPassword("Vault password: ")
		if err != nil {
			return err
		}
		defer vcrypto.Zero(pw)
		if len(pw) == 0 {
			return errors.New("empty password")
		}
		pw2, err := tty.ReadPassword("Repeat password: ")
		if err != nil {
			return err
		}
		defer vcrypto.Zero(pw2)
		if !bytes.Equal(pw, pw2) {
			return errors.New("passwords do not match")
		}
		if key, head, err = passwordKey(pw); err != nil {
			return err
		}
		cfg.KeyType = vaultfile.KeyTypePassword
	} else {
		fmt.Println("Initialisiere Vault mit ASYMMETRISCHER Verschlüsselung (RSA-OAEP / ECDH-AES)...")
		priv, err := keys.Load(*keyPath, passphrasePrompt(*keyPath))
		if err != nil {
			return err
		}
		if cfg.KeyType, err = keys.KeyType(priv); err != nil {
			return err
		}
		if key, head, err = keys.Wrap(priv); err != nil {
			return err
		}
	}
	defer vcrypto.Zero(key)
	cfg.HeadLen = len(head)

	data, err := vaultfile.Create(head, key, &vaultfile.Payload{Credentials: map[string]string{}})
	if err != nil {
		return err
	}
	for _, p := range existing {
		bak, err := vaultfile.Backup(p, vaultPath)
		if err != nil {
			return fmt.Errorf("backing up existing vault: %w", err)
		}
		fmt.Printf("Previous vault moved to %s\n", bak)
	}
	if err := vaultfile.WriteAtomic(vaultPath, data); err != nil {
		return fmt.Errorf("writing vault: %w", err)
	}
	fmt.Printf("Vault created: %s (keytype: %s)\n", vaultPath, cfg.KeyType)

	pid, err := spawn.Start(key, cfg)
	if err != nil {
		return fmt.Errorf("vault created, but vaultd failed to start: %w", err)
	}
	fmt.Printf("vaultd started (PID: %d, %s)\n", pid, describeTimeouts(idle, ttl))
	return nil
}

// passwordKey creates a fresh salt (= the file head) and derives the key.
func passwordKey(pw []byte) (key, salt []byte, err error) {
	if salt, err = vcrypto.Random(vaultfile.SaltSize); err != nil {
		return nil, nil, err
	}
	return vcrypto.DeriveKey(pw, salt, vaultfile.PBKDF2Iterations), salt, nil
}

func describeTimeouts(idle, ttl time.Duration) string {
	f := func(d time.Duration) string {
		if d == 0 {
			return "never"
		}
		return fmtDur(d)
	}
	return "auto-stop: idle " + f(idle) + ", max " + f(ttl)
}

// fmtDur prints 8h, 30m, 1h30m, 45s instead of 8h0m0s.
func fmtDur(d time.Duration) string {
	s := d.Round(time.Second).String()
	if strings.HasSuffix(s, "m0s") {
		s = strings.TrimSuffix(s, "0s")
	}
	if strings.HasSuffix(s, "h0m") {
		s = strings.TrimSuffix(s, "0m")
	}
	return s
}

// ---------------------------------------------------------------- daemon start

func cmdDaemonStart(args []string) error {
	const use = "usage: vault daemon start [--password | --key PATH] [--idle DUR] [--ttl DUR]"
	fs := flag.NewFlagSet("daemon start", flag.ContinueOnError)
	usePw := fs.Bool("password", false, "unlock with password (default)")
	keyPath := fs.String("key", "", "unlock with this SSH private key")
	timeouts := timeoutFlags(fs)
	if err := fs.Parse(args); err != nil || fs.NArg() > 0 || (*usePw && *keyPath != "") {
		return usageErr(use)
	}
	idle, ttl, err := timeouts()
	if err != nil {
		return err
	}

	vaultPath, err := vaultfile.DefaultPath()
	if err != nil {
		return err
	}
	legacyPath, err := vaultfile.LegacyPath()
	if err != nil {
		return err
	}
	migrate := !vaultfile.Exists(vaultPath) && vaultfile.Exists(legacyPath)
	var f *vaultfile.File
	if !migrate {
		if f, err = vaultfile.Load(vaultPath); err != nil {
			return err
		}
	}
	if resp, err := ipc.Call(ipc.Request{Op: "ping"}); err == nil && resp.OK {
		return fmt.Errorf("vaultd is already running (PID: %d)", resp.PID)
	}

	var key []byte
	cfg := spawn.Config{IdleTimeout: idle, MaxLifetime: ttl}
	if migrate {
		key, cfg.KeyType, cfg.HeadLen, err = migrateLegacy(legacyPath, vaultPath, *usePw, *keyPath)
		if err != nil {
			return err
		}
	} else if *keyPath == "" {
		salt, err := f.Head(vaultfile.SaltSize)
		if err != nil {
			return err
		}
		pw, err := tty.ReadPassword("Vault password: ")
		if err != nil {
			return err
		}
		key = vcrypto.DeriveKey(pw, salt, vaultfile.PBKDF2Iterations)
		vcrypto.Zero(pw)
		cfg.KeyType, cfg.HeadLen = vaultfile.KeyTypePassword, vaultfile.SaltSize
	} else {
		priv, err := keys.Load(*keyPath, passphrasePrompt(*keyPath))
		if err != nil {
			return err
		}
		if cfg.KeyType, err = keys.KeyType(priv); err != nil {
			return err
		}
		if cfg.HeadLen, err = keys.HeadLen(priv); err != nil {
			return err
		}
		head, err := f.Head(cfg.HeadLen)
		if err != nil {
			return err
		}
		if key, err = keys.Unwrap(priv, head); err != nil {
			return err
		}
	}
	defer vcrypto.Zero(key)

	if !migrate {
		if _, err := f.Open(cfg.HeadLen, key); err != nil {
			if !*usePw && *keyPath == "" {
				return fmt.Errorf("%w; if the vault is protected by an SSH key, use: vault daemon start --key PATH", err)
			}
			return err
		}
	}
	pid, err := spawn.Start(key, cfg)
	if err != nil {
		return fmt.Errorf("vaultd failed to start: %w", err)
	}
	fmt.Printf("vaultd started (PID: %d, %s)\n", pid, describeTimeouts(idle, ttl))
	return nil
}

// migrateLegacy converts a v1 ~/.vault (plaintext JSON header) into the
// opaque v2 format at vaultPath with a fresh salt / wrapped key, verifies
// the result and removes the old file. It returns the new key.
func migrateLegacy(legacyPath, vaultPath string, usePw bool, keyPath string) (key []byte, keyType string, headLen int, err error) {
	lf, err := vaultfile.LoadLegacy(legacyPath)
	if err != nil {
		return nil, "", 0, fmt.Errorf("%s: %w", legacyPath, err)
	}
	isPw := lf.Header.KeyType == vaultfile.KeyTypePassword
	switch {
	case usePw && !isPw, keyPath == "" && !isPw:
		return nil, "", 0, fmt.Errorf("this vault is protected by an SSH key (%s); use: vault daemon start --key PATH", lf.Header.KeyType)
	case keyPath != "" && isPw:
		return nil, "", 0, errors.New("this vault is password protected; use: vault daemon start --password")
	}

	var oldKey, head []byte
	if isPw {
		salt, err := hex.DecodeString(lf.Header.Salt)
		if err != nil || lf.Header.PBKDF2Iterations <= 0 {
			return nil, "", 0, errors.New("invalid salt in legacy vault header")
		}
		pw, err := tty.ReadPassword("Vault password: ")
		if err != nil {
			return nil, "", 0, err
		}
		defer vcrypto.Zero(pw)
		oldKey = vcrypto.DeriveKey(pw, salt, lf.Header.PBKDF2Iterations)
		defer vcrypto.Zero(oldKey)
		if _, err := lf.Open(oldKey); err != nil {
			return nil, "", 0, err
		}
		if key, head, err = passwordKey(pw); err != nil {
			return nil, "", 0, err
		}
		keyType = vaultfile.KeyTypePassword
	} else {
		priv, err := keys.Load(keyPath, passphrasePrompt(keyPath))
		if err != nil {
			return nil, "", 0, err
		}
		if oldKey, err = keys.UnwrapLegacy(priv, &lf.Header); err != nil {
			return nil, "", 0, err
		}
		defer vcrypto.Zero(oldKey)
		if _, err := lf.Open(oldKey); err != nil {
			return nil, "", 0, err
		}
		if key, head, err = keys.Wrap(priv); err != nil {
			return nil, "", 0, err
		}
		keyType = lf.Header.KeyType
	}
	fail := func(err error) ([]byte, string, int, error) {
		vcrypto.Zero(key)
		return nil, "", 0, fmt.Errorf("migrating %s: %w (old file left untouched)", legacyPath, err)
	}
	p, err := lf.Open(oldKey)
	if err != nil {
		return fail(err)
	}
	data, err := vaultfile.Create(head, key, p)
	if err != nil {
		return fail(err)
	}
	if err := vaultfile.WriteAtomic(vaultPath, data); err != nil {
		return fail(err)
	}
	nf, err := vaultfile.Load(vaultPath)
	if err == nil {
		_, err = nf.Open(len(head), key)
	}
	if err != nil {
		os.Remove(vaultPath)
		return fail(fmt.Errorf("verifying migrated vault: %w", err))
	}
	if err := os.Remove(legacyPath); err != nil {
		fmt.Fprintf(os.Stderr, "warning: migrated, but could not remove %s: %v\n", legacyPath, err)
	}
	fmt.Printf("Migrated %s to the new format: %s (old file removed)\n", legacyPath, vaultPath)
	return key, keyType, len(head), nil
}

func passphrasePrompt(path string) keys.PassphraseFunc {
	return func() ([]byte, error) { return tty.ReadPassword("Passphrase for " + path + ": ") }
}

// ---------------------------------------------------------------- add / get / list / rm

func call(req ipc.Request) (*ipc.Response, error) {
	resp, err := ipc.Call(req)
	if errors.Is(err, ipc.ErrNotRunning) {
		return nil, errors.New("vaultd not running (start it with 'vault daemon start')")
	}
	if err != nil {
		return nil, err
	}
	if !resp.OK {
		return nil, errors.New(resp.Error)
	}
	return resp, nil
}

func cmdAdd(args []string) error {
	if len(args) < 1 || len(args) > 2 || args[0] == "" {
		return usageErr("usage: vault add KEY [VALUE]")
	}
	var value string
	if len(args) == 2 {
		value = args[1]
	} else if tty.IsTerminal(os.Stdin.Fd()) {
		v, err := tty.ReadPassword("Value for " + args[0] + ": ")
		if err != nil {
			return err
		}
		value = string(v)
		vcrypto.Zero(v)
	} else {
		b, err := io.ReadAll(io.LimitReader(bufio.NewReader(os.Stdin), server.MaxValueLen+1))
		if err != nil {
			return fmt.Errorf("reading value from stdin: %w", err)
		}
		if len(b) > server.MaxValueLen {
			return errors.New("value too large")
		}
		b = bytes.TrimSuffix(b, []byte("\n"))
		b = bytes.TrimSuffix(b, []byte("\r"))
		value = string(b)
		vcrypto.Zero(b)
	}
	if _, err := call(ipc.Request{Op: "add", Key: args[0], Value: value}); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "stored: %s\n", args[0])
	return nil
}

func cmdGet(args []string) error {
	if len(args) != 1 {
		return usageErr("usage: vault get KEY")
	}
	resp, err := call(ipc.Request{Op: "get", Key: args[0]})
	if err != nil {
		return err
	}
	// Raw value when piped (e.g. into xclip); newline for humans.
	if tty.IsTerminal(os.Stdout.Fd()) {
		fmt.Println(resp.Value)
	} else {
		fmt.Print(resp.Value)
	}
	return nil
}

func cmdList(args []string) error {
	if len(args) != 0 {
		return usageErr("usage: vault list")
	}
	resp, err := call(ipc.Request{Op: "list"})
	if err != nil {
		return err
	}
	for _, k := range resp.Keys {
		fmt.Println(k)
	}
	return nil
}

func cmdRm(args []string) error {
	if len(args) != 1 {
		return usageErr("usage: vault rm KEY")
	}
	if _, err := call(ipc.Request{Op: "delete", Key: args[0]}); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "deleted: %s\n", args[0])
	return nil
}

// ---------------------------------------------------------------- status / stop

func cmdStatus() error {
	resp, err := ipc.Call(ipc.Request{Op: "ping"})
	if err != nil || !resp.OK {
		fmt.Println("not running")
		os.Exit(3)
	}
	up := time.Since(time.Unix(resp.StartedAt, 0)).Round(time.Second)
	stop := "auto-stop: never"
	if resp.ExpiresAt != 0 {
		left := time.Until(time.Unix(resp.ExpiresAt, 0)).Round(time.Second)
		stop = fmt.Sprintf("auto-stop in %s (%s)", fmtDur(max(left, 0)),
			strings.TrimPrefix(describeTimeouts(time.Duration(resp.IdleTimeout)*time.Second, time.Duration(resp.MaxLifetime)*time.Second), "auto-stop: "))
	}
	fmt.Printf("running (PID: %d, uptime: %s, keytype: %s, %s)\n", resp.PID, up, resp.KeyType, stop)
	return nil
}

func cmdPath() error {
	p, err := vaultfile.DefaultPath()
	if err != nil {
		return err
	}
	fmt.Println(p)
	return nil
}

func cmdStop() error {
	pidPath, err := ipc.PIDPath()
	if err != nil {
		return err
	}
	b, err := os.ReadFile(pidPath)
	if err != nil {
		if _, perr := ipc.Call(ipc.Request{Op: "ping"}); perr == nil {
			return errors.New("vaultd is running but its pid file is missing")
		}
		fmt.Println("not running")
		return nil
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil || pid <= 1 {
		return fmt.Errorf("invalid pid file %s", pidPath)
	}
	if !isOurVaultd(pid) {
		os.Remove(pidPath)
		fmt.Println("not running (removed stale pid file)")
		return nil
	}
	if err := syscall.Kill(pid, syscall.SIGTERM); err != nil {
		return fmt.Errorf("sending SIGTERM to %d: %w", pid, err)
	}
	for i := 0; i < 100; i++ {
		if syscall.Kill(pid, 0) == syscall.ESRCH || !isOurVaultd(pid) {
			fmt.Printf("vaultd stopped (PID: %d)\n", pid)
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return fmt.Errorf("vaultd (PID: %d) did not exit within 5s", pid)
}

// isOurVaultd guards against PID reuse: the process must be named vaultd,
// belong to us and not be a zombie.
func isOurVaultd(pid int) bool {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return false
	}
	var name, state string
	uid := -1
	for _, line := range strings.Split(string(b), "\n") {
		k, v, _ := strings.Cut(line, ":")
		v = strings.TrimSpace(v)
		switch k {
		case "Name":
			name = v
		case "State":
			state = v
		case "Uid":
			if f := strings.Fields(v); len(f) > 0 {
				uid, _ = strconv.Atoi(f[0])
			}
		}
	}
	return name == spawn.DaemonName && uid == os.Getuid() && !strings.HasPrefix(state, "Z")
}
