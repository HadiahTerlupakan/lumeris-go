package main
import (
	"context"
	"fmt"
	"github.com/jackc/pgx/v5/pgxpool"
)
func main() {
	ctx := context.Background()
	pool, _ := pgxpool.New(ctx, "postgres://lumeris:lumeris@localhost:5432/lumeris?sslmode=disable")
	defer pool.Close()
	
	fmt.Println("=== VERIFY SCHEMA MIGRATION ===\n")
	
	// Check if 'login' table exists
	var loginExists bool
	pool.QueryRow(ctx, "SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = 'login')").Scan(&loginExists)
	fmt.Printf("Table 'login' exists: %v\n", loginExists)
	
	// Check if 'accounts' table still exists
	var accountsExists bool
	pool.QueryRow(ctx, "SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = 'accounts')").Scan(&accountsExists)
	fmt.Printf("Table 'accounts' exists: %v\n\n", accountsExists)
	
	if loginExists {
		// Check columns in login table
		fmt.Println("Columns in 'login' table:")
		rows, _ := pool.Query(ctx, `
			SELECT column_name, data_type 
			FROM information_schema.columns 
			WHERE table_name = 'login' 
			ORDER BY ordinal_position
		`)
		defer rows.Close()
		for rows.Next() {
			var colName, dataType string
			rows.Scan(&colName, &dataType)
			fmt.Printf("  - %s (%s)\n", colName, dataType)
		}
		
		// Check data migrated
		var count int
		pool.QueryRow(ctx, "SELECT COUNT(*) FROM login").Scan(&count)
		fmt.Printf("\nTotal accounts in 'login': %d\n", count)
		
		// Show testlogin account
		var username, password string
		var accountID int
		err := pool.QueryRow(ctx, "SELECT account_id, username, password FROM login WHERE username='testlogin'").Scan(&accountID, &username, &password)
		if err == nil {
			fmt.Printf("\nAccount 'testlogin':\n")
			fmt.Printf("  ID: %d\n", accountID)
			fmt.Printf("  Username: %s\n", username)
			fmt.Printf("  Password (MD5): %s\n", password)
		}
	}
}
