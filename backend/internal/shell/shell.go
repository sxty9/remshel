// Package shell launches a per-user login shell on a PTY and bridges it to the
// caller, recording the full session. Two invariants make this safe:
//
//  1. The shell ALWAYS runs as the requesting user via `sudo -u <user>` through the
//     narrow remshel-login wrapper. remshel (the daemon) never runs a shell itself
//     and never passes a shell path — sudoers pins the command to the wrapper and the
//     run-as set to %smbusers, so the worst a bug could do is open a holistic user's
//     own shell. The shell therefore has exactly that user's OS rights, nothing more.
//  2. The username comes only from the validated session (never request input), so a
//     caller can only ever reach their own account.
//
// The login shell in /etc/passwd is the single source of truth for "is this user
// shell-entitled" — the same field privleg toggles. A nologin/false shell => no access.
package shell

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/creack/pty"
)

// loginWrapper is the only command remshel is allowed (by sudoers) to run as another
// user. It execs that user's own login shell as a login shell, refusing nologin.
const loginWrapper = "/usr/local/sbin/remshel-login"

// isDisabledShell reports whether a login shell means "no interactive access".
func isDisabledShell(sh string) bool {
	if strings.TrimSpace(sh) == "" {
		return true
	}
	switch filepath.Base(sh) {
	case "nologin", "false":
		return true
	}
	return false
}

// LoginShell returns the user's configured login shell (passwd field 7), read live
// from the OS via getent (honours all NSS sources), and whether the account exists.
func LoginShell(username string) (string, bool) {
	out, err := exec.Command("getent", "passwd", username).Output()
	if err != nil {
		return "", false
	}
	fields := strings.Split(strings.TrimRight(string(out), "\n"), ":")
	if len(fields) < 7 {
		return "", false
	}
	return fields[6], true
}

// Enabled reports whether the user is shell-entitled: the account exists and its login
// shell is a real shell (not nologin/false). Returns the resolved shell either way.
func Enabled(username string) (shell string, ok bool) {
	sh, found := LoginShell(username)
	if !found || isDisabledShell(sh) {
		return sh, false
	}
	return sh, true
}

// Session is a running login shell attached to a PTY.
type Session struct {
	cmd  *exec.Cmd
	Ptmx *os.File
}

// Start launches username's login shell on a fresh PTY, as that user, via
// `sudo -n -u <user> -- /usr/local/sbin/remshel-login`. No shell path is passed, so
// remshel cannot be coerced into running anything but the wrapper. username MUST come
// from the authenticated session.
func Start(username string) (*Session, error) {
	cmd := exec.Command("sudo", "-n", "-u", username, "--", loginWrapper)
	// sudo resets the environment (env_reset); the wrapper sets the real login env for
	// the target user. We only seed sudo's own minimal env.
	cmd.Env = []string{
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"TERM=xterm-256color",
	}
	ptmx, err := pty.Start(cmd)
	if err != nil {
		return nil, err
	}
	return &Session{cmd: cmd, Ptmx: ptmx}, nil
}

// Resize sets the PTY window size.
func (s *Session) Resize(rows, cols uint16) error {
	return pty.Setsize(s.Ptmx, &pty.Winsize{Rows: rows, Cols: cols})
}

// Close terminates the shell and releases the PTY. Idempotent.
func (s *Session) Close() {
	if s.Ptmx != nil {
		_ = s.Ptmx.Close()
	}
	if s.cmd != nil && s.cmd.Process != nil {
		_ = s.cmd.Process.Kill()
		_ = s.cmd.Wait()
	}
}
