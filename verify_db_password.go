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
	
	var storedPassword string
	err := pool.QueryRow(ctx, "SELECT password FROM login WHERE username='testlogin'").Scan(&storedPassword)
	if err != nil {
		fmt.Printf("Query failed: %v\n", err)
		return
	}
	
	expectedMD5 := fmt.Sprintf("%x", md5.Sum([]byte("test123")))
	
	fmt.Println("=== VERIFY DATABASE PASSWORD ===")
	fmt.Printf("Username: testlogin\n")
	fmt.Printf("Password plaintext: test123\n")
	fmt.Printf("Expected MD5: %s\n", expectedMD5)
	fmt.Printf("Stored in DB: %s\n", storedPassword)
	fmt.Printf("Match: %v\n\n", expectedMD5 == storedPassword)
	
	if expectedMD5 != storedPassword {
		fmt.Println("❌ DATABASE PASSWORD CORRUPTION!")
		fmt.Println("Run: UPDATE login SET password='cc03e747a6afbbcbf8be7668acfebee5' WHERE username='testlogin';")
	} else {
		fmt.Println("✅ Database password is correct!")
		fmt.Println("\nIf challenge still fails, the problem is in:")
		fmt.Println("1. Client is NOT using MD5 for password")
		fmt.Println("2. Client is using DIFFERENT challenge format")
		fmt.Println("3. Encryption/decryption issue in packet transmission")
	}
}
