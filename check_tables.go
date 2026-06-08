package main
import (
	"context"
	"fmt"
	"github.com/jackc/pgx/v5/pgxpool"
)
func main() {
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, "postgres://lumeris:lumeris@localhost:5432/lumeris?sslmode=disable")
	if err != nil {
		fmt.Printf("Failed to connect: %v\n", err)
		return
	}
	defer pool.Close()
	
	// Check if 'login' table exists
	var exists bool
	err = pool.QueryRow(ctx, "SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = 'login')").Scan(&exists)
	if err != nil {
		fmt.Printf("Query failed: %v\n", err)
		return
	}
	
	fmt.Printf("Table 'login' exists: %v\n", exists)
	
	// List all tables
	rows, err := pool.Query(ctx, "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' ORDER BY table_name")
	if err != nil {
		fmt.Printf("Query failed: %v\n", err)
		return
	}
	defer rows.Close()
	
	fmt.Println("\n=== ALL TABLES IN DATABASE ===")
	for rows.Next() {
		var tableName string
		rows.Scan(&tableName)
		fmt.Printf("- %s\n", tableName)
	}
}
