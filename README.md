# vault / vaultd

A small credential vault for the shell, built on an agent model like `ssh-agent`.
`vaultd` holds the vault key in memory and answers requests on a Unix socket.
The key never leaves the daemon and is never exported to the environment.

## Usage

```sh
vault init --password                 # symmetric:  AES-256-GCM, key = PBKDF2-SHA256(password, 100k)
vault init --key ~/.ssh/id_ed25519    # asymmetric: RSA-OAEP / ECDH (Ed25519, ECDSA P-256)
vault init ... --force                # replace existing vault (old one kept as <vault file>.<epoch>)
vault init ... --idle 10m --ttl 2h    # auto-stop of vaultd (defaults: --idle 30m, --ttl 8h; 0 = never)

vault add github_token ghp_xxx        # value in argv (visible in ps / shell history!)
vault add github_token                # hidden prompt on the terminal
cat key.pem | vault add deploy_key    # from stdin (one trailing newline is stripped)
vault get github_token                # raw value when piped, with newline on a terminal
vault list
vault rm github_token

vault status                          # running (PID: 1234, uptime: 5m3s, keytype: password, auto-stop in 25m (idle 30m, max 8h))
                                      # | not running (exit 3)
vault stop                            # SIGTERM to vaultd
vault daemon start                    # after reboot / stop / auto-stop (password is the default)
vault daemon start --key ~/.ssh/id_ed25519 [--idle DUR] [--ttl DUR]
vault path                            # where the vault file is (for backups)
```

Passwords and key passphrases are **only** read from `/dev/tty`, never from
argv, environment or stdin.

## Automatic shutdown

vaultd exits on its own, whichever comes first:

* `--idle` (default 30m): no `add`/`get`/`list`/`rm` request for that long. `vault status` does not count as activity.
* `--ttl` (default 8h): that long after start, no matter how busy.

`0` disables either one. Both are measured in wall-clock time (re-checked at least every 5 s),
so time a laptop spends suspended counts. On expiry vaultd behaves exactly like on `vault stop`:
socket and pid file are removed and the key is zeroed. Afterwards run `vault daemon start` again.

## Architecture

```
vault init / daemon start                      vaultd
  read password/passphrase from /dev/tty         read hex(key) + config from fd 3, close it
  derive (PBKDF2) or unwrap (RSA/ECDH) key       prctl(PR_SET_NAME "vaultd"), PR_SET_DUMPABLE=0
  verify key decrypts vault file                   verify key decrypts vault file
  spawn vaultd: key → pipe fd 3  ───────────▶    listen $XDG_RUNTIME_DIR/vault.sock (0600)
                  status ◀── pipe fd 4 ───────   write vault.pid (0600), "OK" on fd 4
                                                 per connection: SO_PEERCRED uid check,
vault add/get/list/rm  ── JSON over socket ──▶    decrypt file, answer, re-encrypt on change
vault stop             ── SIGTERM (pid file) ─▶   remove socket + pid file, zero key, exit
                       idle / ttl expired    ─▶   (same)
```

* vaultd's argv is just `vaultd`. Its environment is only `HOME` and `XDG_RUNTIME_DIR`. It runs in its own session with cwd `/`.
* `PR_SET_DUMPABLE=0` means other processes of the same user can't ptrace it or read `/proc/PID/{mem,environ,cwd}`, and it writes no core dumps.
* The client checks the daemon's UID too (mutual SO_PEERCRED).
* If `XDG_RUNTIME_DIR` is unset, `/tmp/vault-<uid>` (0700, ownership checked) is used.
* `vault stop` only signals the PID if `/proc/PID/status` says it is a `vaultd` owned by you, which protects against PID reuse.

## Vault file

**Location:** `~/.local/share/.<16 hex>` (0600, written atomically). The name is
`HMAC-SHA256(key = /etc/machine-id, "vault-file:" + uid)`, truncated to 8 bytes: stable for a
machine and user, no pointer file needed, and nothing in it says "vault". `vault path` prints it.
Because the machine-id is part of the name, a home directory copied to another machine will not
find its vault automatically; move the file to the name `vault path` prints there.

**Format (v2):** fully opaque — no magic, version, JSON, key type or public key.

```
head ‖ nonce(12) ‖ AES-256-GCM ciphertext          (head = GCM additional authenticated data)

head:  password         16-byte PBKDF2-SHA256 salt (100k iterations)
       ssh-rsa          RSA-OAEP-SHA256 wrapped AES key (modulus size, e.g. 256 / 512 bytes)
       ssh-ed25519      ephemeral X25519 public key (32 bytes);  AES key = SHA256(shared ‖ "vault-ed25519")
       ssh-ecdsa-p256   X coordinate of the ephemeral P-256 key (32 bytes, Y forced even);
                        AES key = SHA256(shared ‖ "vault-ecdsa-p256")
```

Every byte is a salt, wrapped key, ephemeral public key, nonce or ciphertext, so the file
looks like random data. The unlock method comes from the user (`--password`, which is the
default, or `--key PATH`) and determines the head length. Consequences:

* A wrong password, a wrong key and the wrong method all fail the same way:
  `failed to decrypt vault (wrong password or key)`.
* Flipping any byte (salt, wrapped key, nonce, ciphertext) makes decryption fail.

Payload: `{"credentials": {"key": "value", ...}}`.

**Migration:** an old `~/.vault` (v1, readable JSON header) is converted on the next
`vault daemon start [--password | --key PATH]`: decrypted with the old key, re-encrypted with a fresh
salt / wrapped key into the new file, verified, then `~/.vault` is deleted. If anything fails, the
old file is left untouched. `vault init` refuses to run while `~/.vault` exists (unless `--force`,
which keeps it as a backup next to the new file).

## Build & test

```sh
make build      # ./vault ./vaultd for the host
make release    # dist/linux-{amd64,arm64}/{vault,vaultd}
make test       # go vet + end-to-end security suite (tests/)
```

`vault` looks for `vaultd` next to itself first, then in `PATH`, so keep both binaries together.
Requires Go ≥ 1.26 (because of golang.org/x/crypto). Linux only (prctl, SO_PEERCRED).

The tests drive the real binaries through a pseudo-terminal, so passwords are
typed exactly like a human would type them. Each test uses a temporary `HOME` and `XDG_RUNTIME_DIR`.
The test for a second user (SO_PEERCRED) only runs with passwordless `sudo`.
Without it, the rejection is still proven at kernel level with a daemon configured for a foreign UID.

## Limits

* Credentials are decrypted per request. Go strings cannot be reliably wiped, so values can linger in vaultd's heap until GC.
  The key itself is mlocked (best effort) and zeroed on shutdown.
* Root can always read process memory.
* PBKDF2 uses 100k iterations (as specified). The opaque format stores no parameters, so raising it later needs a migration like the v1 → v2 one.
