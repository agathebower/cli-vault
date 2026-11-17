// Package tty reads secrets from the controlling terminal (/dev/tty) with
// echo disabled. Secrets are never read from argv, env or stdin.
package tty

import (
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"unsafe"
)

func ioctlTermios(fd uintptr, req uintptr, t *syscall.Termios) error {
	_, _, e := syscall.Syscall(syscall.SYS_IOCTL, fd, req, uintptr(unsafe.Pointer(t)))
	if e != 0 {
		return e
	}
	return nil
}

// IsTerminal reports whether fd refers to a terminal.
func IsTerminal(fd uintptr) bool {
	var t syscall.Termios
	return ioctlTermios(fd, syscall.TCGETS, &t) == nil
}

// ReadPassword prints prompt on /dev/tty and reads one line without echo.
// The trailing newline is stripped. The caller should zero the result.
func ReadPassword(prompt string) ([]byte, error) {
	f, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return nil, errors.New("no terminal available (/dev/tty): secrets must be entered interactively")
	}
	defer f.Close()
	fd := f.Fd()

	var old syscall.Termios
	if err := ioctlTermios(fd, syscall.TCGETS, &old); err != nil {
		return nil, fmt.Errorf("cannot read terminal settings: %w", err)
	}
	noEcho := old
	noEcho.Lflag &^= syscall.ECHO
	noEcho.Lflag |= syscall.ICANON | syscall.ISIG
	if err := ioctlTermios(fd, syscall.TCSETS, &noEcho); err != nil {
		return nil, fmt.Errorf("cannot disable echo: %w", err)
	}

	// Restore echo if the user hits Ctrl-C while typing.
	sig := make(chan os.Signal, 1)
	done := make(chan struct{})
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		select {
		case <-sig:
			ioctlTermios(fd, syscall.TCSETS, &old)
			f.WriteString("\n")
			os.Exit(130)
		case <-done:
		}
	}()
	defer func() {
		signal.Stop(sig)
		close(done)
		ioctlTermios(fd, syscall.TCSETS, &old)
		f.WriteString("\n")
	}()

	if _, err := f.WriteString(prompt); err != nil {
		return nil, err
	}

	var line []byte
	buf := make([]byte, 256)
	for {
		n, err := f.Read(buf)
		line = append(line, buf[:n]...)
		if i := indexNL(line); i >= 0 {
			for j := i; j < len(line); j++ {
				line[j] = 0
			}
			line = line[:i]
			break
		}
		if err != nil || n == 0 {
			if len(line) == 0 {
				return nil, errors.New("no input")
			}
			break
		}
		if len(line) > 64*1024 {
			return nil, errors.New("input too long")
		}
	}
	for i := range buf {
		buf[i] = 0
	}
	if n := len(line); n > 0 && line[n-1] == '\r' {
		line = line[:n-1]
	}
	return line, nil
}

func indexNL(b []byte) int {
	for i, c := range b {
		if c == '\n' {
			return i
		}
	}
	return -1
}
