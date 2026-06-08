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
	
	_, err := pool.Exec(ctx, "DELETE FROM login WHERE username='testlogin'")
	if err != nil {
		fmt.Printf("Delete failed: %v\n", err)
		return
	}
	fmt.Println("✅ testlogin account deleted")
}
