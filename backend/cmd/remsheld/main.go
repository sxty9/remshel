// Command remsheld is the remshel service daemon: it serves a browser terminal under
// /api/services/remshel/ that bridges a WebSocket to a login shell running AS the
// authenticated holistic user, confined to that user's own OS rights. It validates the
// shared holistic session (a signed JWT in the h_access cookie) without any RPC to the
// holistic backend. It runs unprivileged and escalates only via the narrow sudo +
// remshel-login wrapper to drop into the target user's shell.
package main

import (
	"context"
	"flag"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"remshel/internal/api"
	"remshel/internal/auth"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:8774", "address to listen on")
	flag.Parse()

	secret, err := auth.LoadSecret()
	if err != nil {
		log.Fatalf("remsheld: %v", err)
	}
	// Admin = membership in this group (the single Linux source of truth). The systemd
	// unit sets REMSHEL_ADMIN_GROUP; the verifier defaults to "sudo" when it is empty.
	v := auth.NewVerifier(secret, os.Getenv("REMSHEL_ADMIN_GROUP"))

	srv := &http.Server{
		Handler:           api.New(v).Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	// Bind synchronously so an "address in use" surfaces here, not in a goroutine.
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatalf("remsheld: listen %s: %v", *listen, err)
	}
	go func() {
		log.Printf("remsheld listening on %s", *listen)
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			log.Fatalf("remsheld: %v", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(ctx)
	log.Print("remsheld stopped")
}
