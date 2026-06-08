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
	
	var passwordHash string
	err := pool.QueryRow(ctx, "SELECT password_hash FROM accounts WHERE username='testlogin'").Scan(&passwordHash)
	if err != nil {
		fmt.Printf("Query failed: %v\n", err)
		return
	}
	
	expectedMD5 := fmt.Sprintf("%x", md5.Sum([]byte("test123")))
	
	fmt.Println("=== VERIFY NEW ACCOUNT ===")
	fmt.Printf("Username: testlogin\n")
	fmt.Printf("Password plaintext: test123\n")
	fmt.Printf("Expected MD5: %s\n", expectedMD5)
	fmt.Printf("Stored MD5:   %s\n", passwordHash)
	fmt.Printf("Match: %v\n\n", expectedMD5 == passwordHash)
	
	if expectedMD5 == passwordHash {
		fmt.Println("✅ Account created correctly!")
		fmt.Println("\nNow login with:")
		fmt.Println("  Username: testlogin")
		fmt.Println("  Password: test123")
	}
}
