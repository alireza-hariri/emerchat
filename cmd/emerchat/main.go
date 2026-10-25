package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"emerchat/internal/server"
	"emerchat/internal/store"
	"emerchat/web"
)

func main() {
	var (
		addr          = flag.String("addr", ":8080", "listen address")
		dbPath        = flag.String("db", "emerchat.db", "SQLite database path")
		filesDir      = flag.String("files", "files", "directory for encrypted attachments and profile pictures")
		maxUploadMB   = flag.Int64("max-upload-mb", 50, "largest attachment in MiB")
		baseURL       = flag.String("base-url", "http://localhost:8080", "public URL, used to print invite links")
		invitePolicy  = flag.String("invite-policy", "all", `who can create invites: "all" or "admins"`)
		trustProxy    = flag.Bool("trust-proxy", false, "trust X-Forwarded-For/-Proto from a reverse proxy")
		secureCookies = flag.Bool("secure-cookies", false, "always set the Secure cookie flag")
		newInvite     = flag.Bool("new-admin-invite", false, "print a new admin invite link and exit")
		startInvite   = flag.Bool("start-invite", true, "print a fresh invite link on every start")
		backup        = flag.String("backup", "", "write a consistent copy of the database to this path and exit")
	)
	flag.Parse()
	if *invitePolicy != "all" && *invitePolicy != "admins" {
		log.Fatalf("-invite-policy must be all or admins")
	}
	if *maxUploadMB <= 0 {
		log.Fatalf("-max-upload-mb must be positive")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	st, err := store.Open(*dbPath)
	if err != nil {
		log.Fatalf("open db: %v", err)
	}
	defer st.Close()

	switch {
	case *backup != "":
		if err := st.Backup(ctx, *backup); err != nil {
			log.Fatalf("backup: %v", err)
		}
		fmt.Println("backup written to", *backup)
		return
	case *newInvite:
		printInvite(ctx, st, *baseURL, true)
		return
	}

	if *startInvite {
		// The first user to join becomes admin; after that, start-up invites are regular.
		n, err := st.CountUsers(ctx)
		if err != nil {
			log.Fatal(err)
		}
		printInvite(ctx, st, *baseURL, n == 0)
	}

	srv, err := server.New(ctx, st, web.FS, server.Config{
		InvitePolicy:  *invitePolicy,
		FilesDir:      *filesDir,
		MaxUpload:     *maxUploadMB << 20,
		TrustProxy:    *trustProxy,
		SecureCookies: *secureCookies,
	})
	if err != nil {
		log.Fatal(err)
	}
	go srv.RunJanitor(ctx, 10*time.Minute)

	hs := &http.Server{
		Addr:              *addr,
		Handler:           srv,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second, // must exceed the 25s poll timeout
		IdleTimeout:       120 * time.Second,
		// Cancel in-flight long polls on shutdown instead of waiting them out.
		BaseContext: func(net.Listener) context.Context { return ctx },
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		hs.Shutdown(shutdownCtx)
	}()
	log.Printf("listening on %s", *addr)
	if err := hs.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}

func printInvite(ctx context.Context, st *store.Store, baseURL string, admin bool) {
	now := time.Now()
	inv, err := st.CreateInvite(ctx, server.NewInviteCode(), 0, admin, now.Add(7*24*time.Hour).UnixMilli(), now.UnixMilli())
	if err != nil {
		log.Fatalf("create invite: %v", err)
	}
	kind := "Invite"
	if admin {
		kind = "Admin invite"
	}
	fmt.Printf("\n  %s (valid 7 days, single use):\n  %s/#/join/%s\n\n", kind, baseURL, inv.Code)
}
