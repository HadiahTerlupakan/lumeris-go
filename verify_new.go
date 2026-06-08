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
	
	var password string
	pool.QueryRow(ctx, "SELECT password FROM login WHERE username='testuser2'").Scan(&password)
	
	expectedMD5 := fmt.Sprintf("%x", md5.Sum([]byte("password123")))
	
	fmt.Printf("Username: testuser2\n")
	fmt.Printf("Password: password123\n")
	fmt.Printf("Expected MD5: %s\n", expectedMD5)
	fmt.Printf("Stored MD5:   %s\n", password)
	fmt.Printf("Match: %v\n", expectedMD5 == password)
}
