package main
import (
	"context"
	"crypto/md5"
	"fmt"
	"github.com/jackc/pgx/v5/pgxpool"
)
func main() {
	ctx := context.Background()
	pool, _ := pgxpool.New(ctx, "postgres://lumeris:lumeris@localhost:5432/lumeris?sslmode=disable")
	defer pool.Close()
	
	// Delete ALL users
	result, _ := pool.Exec(ctx, "DELETE FROM login")
	fmt.Printf("✅ Deleted %d users\n\n", result.RowsAffected())
	
	// Create fresh user: testuser / test123
	username := "testuser"
	password := "test123"
	md5Hash := fmt.Sprintf("%x", md5.Sum([]byte(password)))
	
	var accountID int
	err := pool.QueryRow(ctx, 
		"INSERT INTO login(username, password, deletepass, gmlevel, banned) VALUES($1,$2,'0000',0,false) RETURNING account_id",
		username, md5Hash).Scan(&accountID)
	
	if err != nil {
		fmt.Printf("Insert failed: %v\n", err)
		return
	}
	
	fmt.Println("=== NEW USER CREATED ===")
	fmt.Printf("Username: %s\n", username)
	fmt.Printf("Password: %s\n", password)
	fmt.Printf("MD5 Hash: %s\n", md5Hash)
	fmt.Printf("Account ID: %d\n", accountID)
	fmt.Println("\n✅ Database reset complete!")
	fmt.Println("\nLogin dengan:")
	fmt.Println("  Username: testuser")
	fmt.Println("  Password: test123")
}
