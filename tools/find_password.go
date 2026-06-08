package main
import (
	"crypto/md5"
	"crypto/sha1"
	"fmt"
)

func main() {
	front := uint32(4078421135)
	back := uint32(2661099620)
	clientSHA1 := "5105bac4a6c0271008ec993f0bce105b1324e81f"
	
	// Try common passwords
	passwords := []string{
		"pass9999",
		"Pass9999",
		"PASSWORD9999",
		"user9999",
		"9999",
		"password",
		"test123",
		"",
		"pass",
		"1234",
		"12345678",
		"admin",
		"root",
	}
	
	fmt.Printf("Looking for password with front=%d, back=%d\n", front, back)
	fmt.Printf("Target SHA1: %s\n\n", clientSHA1)
	
	for _, pw := range passwords {
		hash := md5.Sum([]byte(pw))
		md5Hex := fmt.Sprintf("%x", hash)
		str := fmt.Sprintf("%d%s%d", front, md5Hex, back)
		sha := sha1.Sum([]byte(str))
		shaHex := fmt.Sprintf("%x", sha)
		
		if shaHex == clientSHA1 {
			fmt.Printf("✓✓✓ PASSWORD FOUND: '%s'\n", pw)
			fmt.Printf("    MD5: %s\n", md5Hex)
			return
		}
	}
	
	fmt.Println("❌ No password match found")
	fmt.Println("\nMaybe client is reading different front/back values?")
}
