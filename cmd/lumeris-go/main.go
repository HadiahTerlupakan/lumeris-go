package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/jackc/pgx/v5/pgxpool"

	"lumeris-go/internal/config"
	"lumeris-go/internal/db"
	"lumeris-go/internal/login"
	"lumeris-go/internal/netio"
	"lumeris-go/internal/register"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.Println("=== Lumeris-Go Server Starting ===")

	// Load config dari environment
	cfg := config.Load()
	log.Printf("Config loaded: ListenValidation=%s, ListenLogin=%s, PortHTTP=%s",
		cfg.ListenValidation, cfg.ListenLogin, cfg.PortHTTP)

	// Connect ke PostgreSQL
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, cfg.DBDSN)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer pool.Close()
	log.Println("Database connected")

	// Run migrations
	if err := db.RunMigrations(ctx, pool, db.MigrationsFS); err != nil {
		log.Fatalf("Failed to run migrations: %v", err)
	}
	log.Println("Migrations completed")

	// Create Store
	store := db.NewPostgresStore(pool)

	// Start Validation listener (:12022)
	validationHandler := login.NewValidationHandler(store)
	validationListener := netio.New(cfg.ListenValidation, validationHandler.Dispatch())
	if err := validationListener.Start(); err != nil {
		log.Fatalf("Validation listener error: %v", err)
	}
	log.Printf("Validation server listening on %s", cfg.ListenValidation)

	// Start Login listener (:12023)
	loginHandler := login.NewLoginHandler(store)
	loginListener := netio.New(cfg.ListenLogin, loginHandler.Dispatch())
	if err := loginListener.Start(); err != nil {
		log.Fatalf("Login listener error: %v", err)
	}
	log.Printf("Login server listening on %s", cfg.ListenLogin)

	// Start HTTP register server
	registerServer := register.NewServer(cfg.PortHTTP, store)
	go func() {
		if err := registerServer.Start(); err != nil {
			log.Fatalf("Register HTTP server error: %v", err)
		}
	}()

	log.Println("=== All servers started successfully ===")

	// Wait for interrupt signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	<-sigCh

	log.Println("Shutting down...")
	validationListener.Close()
	loginListener.Close()
	registerServer.Stop(ctx)
	log.Println("Server stopped")
}
