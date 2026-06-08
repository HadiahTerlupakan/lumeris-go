package main
import (
	"context"
	"fmt"
	"github.com/jackc/pgx/v5/pgxpool"
	"lumeris-go/internal/db"
)
func main() {
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, "postgres://lumeris:lumeris@localhost:5432/lumeris?sslmode=disable")
	if err != nil {
		fmt.Printf("Failed to connect: %v\n", err)
		return
	}
	defer pool.Close()
	
	if err := db.RunMigrations(ctx, pool, db.MigrationsFS); err != nil {
		fmt.Printf("Migration failed: %v\n", err)
		return
	}
	
	fmt.Println("✅ Migration completed successfully!")
}
