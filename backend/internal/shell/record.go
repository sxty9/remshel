package shell

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Recorder writes a full, replayable transcript of a session (input AND output) to a
// JSONL file under <stateDir>/sessions/<user>/. Files are owned by the remshel service
// account and mode 0600 — the session user cannot read or tamper with their own
// recording. The full audit is mandatory: a session that cannot be recorded is refused.
//
// Format: a header object, then one event object per line:
//
//	{"type":"header","version":1,"user":"alice","shell":"/bin/bash","rows":24,"cols":80,"startedAt":"..."}
//	{"t":12,"dir":"o","b":"<base64>"}   // bytes from the shell (output)
//	{"t":15,"dir":"i","b":"<base64>"}   // bytes to the shell (input/keystrokes)
//	{"type":"end","t":98213}
//
// NOTE: input capture includes everything typed, which may contain secrets entered at
// prompts (e.g. a sudo password). Recordings are access-restricted accordingly.
type Recorder struct {
	mu    sync.Mutex
	f     *os.File
	start time.Time
}

// NewRecorder opens a fresh transcript file for the session.
func NewRecorder(stateDir, username, shell string, rows, cols uint16) (*Recorder, error) {
	udir := filepath.Join(stateDir, "sessions", username)
	if err := os.MkdirAll(udir, 0o700); err != nil {
		return nil, err
	}
	start := time.Now()
	// Nanosecond timestamp keeps filenames unique even for back-to-back sessions.
	fname := start.UTC().Format("20060102T150405.000000000Z") + ".jsonl"
	f, err := os.OpenFile(filepath.Join(udir, fname), os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
	if err != nil {
		return nil, err
	}
	r := &Recorder{f: f, start: start}
	r.write(map[string]any{
		"type":      "header",
		"version":   1,
		"user":      username,
		"shell":     shell,
		"rows":      rows,
		"cols":      cols,
		"startedAt": start.UTC().Format(time.RFC3339Nano),
	})
	return r, nil
}

// Event records a chunk of session I/O. dir is "i" (to the shell) or "o" (from it).
func (r *Recorder) Event(dir string, b []byte) {
	if r == nil || len(b) == 0 {
		return
	}
	r.write(map[string]any{
		"t":   time.Since(r.start).Milliseconds(),
		"dir": dir,
		"b":   base64.StdEncoding.EncodeToString(b),
	})
}

// Close writes the end marker and closes the file. Idempotent-safe for a nil receiver.
func (r *Recorder) Close() {
	if r == nil {
		return
	}
	r.write(map[string]any{"type": "end", "t": time.Since(r.start).Milliseconds()})
	r.mu.Lock()
	defer r.mu.Unlock()
	_ = r.f.Close()
}

// Path returns the transcript file path (for logging).
func (r *Recorder) Path() string {
	if r == nil {
		return ""
	}
	return r.f.Name()
}

func (r *Recorder) write(v any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.f == nil {
		return
	}
	b, err := json.Marshal(v)
	if err != nil {
		return
	}
	_, _ = fmt.Fprintf(r.f, "%s\n", b)
}
