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
	
	rows, err := pool.Query(ctx, "SELECT username, password_hash FROM accounts LIMIT 10")
	if err != nil {
		fmt.Printf("Query failed: %v\n", err)
		return
	}
	defer rows.Close()
	
	fmt.Println("=== ACCOUNTS IN DATABASE ===")
	for rows.Next() {
		var username, passwordHash string
		rows.Scan(&username, &passwordHash)
		fmt.Printf("Username: %s\nPassword Hash (MD5): %s\n\n", username, passwordHash)
	}
}
