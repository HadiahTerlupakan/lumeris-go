package main
import (
	"database/sql"
	"fmt"
	_ "github.com/mattn/go-sqlite3"
	"crypto/md5"
)
func main() {
	db, _ := sql.Open("sqlite3", "lumeris.db")
	defer db.Close()
	
	var username, pass string
	db.QueryRow("SELECT username, password FROM accounts WHERE username='dummy2'").Scan(&username, &pass)
	fmt.Printf("Username: %s\nStored MD5: %s\n", username, pass)
	
	// Calculate MD5 of test123
	test123MD5 := fmt.Sprintf("%x", md5.Sum([]byte("test123")))
	fmt.Printf("test123 MD5: %s\n", test123MD5)
	fmt.Printf("Match: %v\n", pass == test123MD5)
}
