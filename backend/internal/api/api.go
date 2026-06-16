// Package api serves remshel's HTTP surface under /api/services/remshel/, behind the
// shared holistic session. It exposes the user's own shell entitlement (status) and a
// WebSocket that bridges a browser terminal to a login shell running AS that user.
//
// Security model:
//   - The target user is ALWAYS the authenticated user (u.Username), never a request
//     parameter, so a caller can only ever open their own shell.
//   - The shell runs as that user (via the sudo + remshel-login wrapper), so it is
//     confined to exactly that user's OS rights.
//   - The login shell in /etc/passwd is the single source of truth for access; a
//     nologin user is refused (the same truth privleg toggles).
//   - The WebSocket upgrade enforces a same-origin check (CSWSH guard); cookies carry
//     the session, so no token travels in the URL.
//   - Every session is fully recorded; if recording cannot start, the session is refused.
package api

import (
	"encoding/json"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"

	"github.com/gorilla/websocket"

	"remshel/internal/auth"
	"remshel/internal/shell"
)

const (
	base    = "/api/services/remshel/"
	service = "remshel"
	version = "0.1.0"
)

// Server wires the session verifier, the audit state dir and the WS upgrader.
type Server struct {
	v        *auth.Verifier
	stateDir string
	upgrader websocket.Upgrader
}

// New builds a server. The audit transcripts live under the systemd StateDirectory
// (/var/lib/remshel), owned by the service account and unreadable to session users.
func New(v *auth.Verifier) *Server {
	dir := os.Getenv("STATE_DIRECTORY")
	if dir == "" {
		dir = "/var/lib/remshel"
	}
	if i := strings.IndexByte(dir, ':'); i >= 0 { // systemd may pass a colon-list
		dir = dir[:i]
	}
	return &Server{
		v:        v,
		stateDir: dir,
		upgrader: websocket.Upgrader{
			ReadBufferSize:  4096,
			WriteBufferSize: 4096,
			CheckOrigin:     sameOrigin,
		},
	}
}

type handler func(w http.ResponseWriter, r *http.Request, u *auth.User)

// Handler returns the routed http.Handler (Go 1.22 method+path patterns).
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+base+"status", s.guard(s.status))
	mux.HandleFunc("GET "+base+"pty", s.pty) // WebSocket upgrade; authenticates internally
	mux.HandleFunc("GET "+base+"health", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	})
	return mux
}

// guard authenticates, then runs the handler with the resolved user.
func (s *Server) guard(h handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u, err := s.v.User(r)
		if err != nil {
			writeErr(w, http.StatusUnauthorized, "Not authenticated")
			return
		}
		h(w, r, u)
	}
}

// status reports whether the caller is shell-entitled (login shell != nologin) and
// which shell would run — read live from the OS, the single source of truth.
func (s *Server) status(w http.ResponseWriter, _ *http.Request, u *auth.User) {
	sh, ok := shell.Enabled(u.Username)
	writeJSON(w, http.StatusOK, map[string]any{
		"service": service,
		"version": version,
		"user":    u.Username,
		"enabled": ok,
		"shell":   sh,
	})
}

// pty upgrades to a WebSocket and bridges it to a login shell running as the caller.
func (s *Server) pty(w http.ResponseWriter, r *http.Request) {
	// Authenticate BEFORE upgrading. Target user = authenticated user, always.
	u, err := s.v.User(r)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, "Not authenticated")
		return
	}
	sh, ok := shell.Enabled(u.Username)
	if !ok {
		writeErr(w, http.StatusForbidden, "Shell access is disabled")
		return
	}

	conn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		return // upgrader already responded (e.g. cross-origin rejected)
	}
	defer conn.Close()

	sess, err := shell.Start(u.Username)
	if err != nil {
		log.Printf("remshel: start shell for %s failed: %v", u.Username, err)
		_ = conn.WriteMessage(websocket.TextMessage, ctrl("error", "Could not start the shell"))
		return
	}
	defer sess.Close()

	// Full audit is mandatory: refuse the session if we cannot record it.
	rec, err := shell.NewRecorder(s.stateDir, u.Username, sh, 24, 80)
	if err != nil {
		log.Printf("remshel: recorder for %s failed: %v", u.Username, err)
		_ = conn.WriteMessage(websocket.TextMessage, ctrl("error", "Audit logging unavailable — session refused"))
		return
	}
	defer rec.Close()

	log.Printf("remshel: session start user=%s shell=%s rec=%s", u.Username, sh, rec.Path())
	bridge(conn, sess, rec)
	log.Printf("remshel: session end   user=%s", u.Username)
}

// bridge pumps PTY<->WebSocket until either side closes. Output (PTY->WS) is sent as
// binary frames; input (WS->PTY) arrives as binary frames; resize arrives as a text
// JSON control frame. Both directions are recorded.
func bridge(conn *websocket.Conn, sess *shell.Session, rec *shell.Recorder) {
	var once sync.Once
	done := make(chan struct{})
	stop := func() { once.Do(func() { close(done) }) }

	// PTY -> WS (shell output). Sole writer of binary frames.
	go func() {
		defer stop()
		buf := make([]byte, 4096)
		for {
			n, err := sess.Ptmx.Read(buf)
			if n > 0 {
				rec.Event("o", buf[:n])
				if conn.WriteMessage(websocket.BinaryMessage, buf[:n]) != nil {
					return
				}
			}
			if err != nil {
				return // shell exited / PTY closed
			}
		}
	}()

	// WS -> PTY (keystrokes + control).
	go func() {
		defer stop()
		for {
			mt, data, err := conn.ReadMessage()
			if err != nil {
				return
			}
			switch mt {
			case websocket.BinaryMessage:
				rec.Event("i", data)
				if _, err := sess.Ptmx.Write(data); err != nil {
					return
				}
			case websocket.TextMessage:
				var c struct {
					Type string `json:"type"`
					Rows uint16 `json:"rows"`
					Cols uint16 `json:"cols"`
				}
				if json.Unmarshal(data, &c) == nil && c.Type == "resize" && c.Rows > 0 && c.Cols > 0 {
					_ = sess.Resize(c.Rows, c.Cols)
				}
			}
		}
	}()

	<-done
}

// sameOrigin is the CheckOrigin guard: the WebSocket Origin host must equal the request
// host (defence against cross-site WebSocket hijacking). Browsers always send Origin.
func sameOrigin(r *http.Request) bool {
	o := r.Header.Get("Origin")
	if o == "" {
		return false
	}
	u, err := url.Parse(o)
	if err != nil {
		return false
	}
	return strings.EqualFold(u.Host, r.Host)
}

func ctrl(typ, msg string) []byte {
	b, _ := json.Marshal(map[string]string{"type": typ, "message": msg})
	return b
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, detail string) {
	writeJSON(w, status, map[string]string{"detail": detail})
}
