package main
import (
	"crypto/md5"
	"crypto/sha1"
	"fmt"
)
func main() {
	front := uint32(434807761)
	back := uint32(1635406830)
	clientSHA1 := "0b92e155aa6338411801251450f62e375a4bd3e9"
	
	// Test berbagai password umum
	passwords := []string{
		"pass9999",
		"Pass9999",
		"PASS9999",
		"user9999",
		"9999",
		"password",
		"test123",
		"",
	}
	
	fmt.Printf("Looking for password that produces SHA1: %s\n", clientSHA1)
	fmt.Printf("Using front=%d, back=%d\n\n", front, back)
	
	for _, pw := range passwords {
		hash := md5.Sum([]byte(pw))
		md5Hex := fmt.Sprintf("%x", hash)
		str := fmt.Sprintf("%d%s%d", front, md5Hex, back)
		sha := sha1.Sum([]byte(str))
		shaHex := fmt.Sprintf("%x", sha)
		
		if shaHex == clientSHA1 {
			fmt.Printf("✓ MATCH FOUND! Password: '%s'\n", pw)
			fmt.Printf("  MD5: %s\n", md5Hex)
			return
		}
	}
	
	fmt.Println("❌ No match found in common passwords")
}
