package main
import (
	"crypto/sha1"
	"fmt"
)

func main() {
	// From log
	front := uint32(1496071116)  // 0x592C3BCC
	back := uint32(3854248468)   // 0xE5BB2A14
	clientSHA1 := "411b49e106bcc0483309e86268c5121c7b7a45e0"
	
	password := "test123" // PLAINTEXT, not MD5
	
	fmt.Println("=== TEST IF CLIENT EXPECTS PLAINTEXT PASSWORD ===\n")
	
	tests := []struct{
		name string
		str  string
	}{
		{"front(dec) + plaintext + back(dec)", fmt.Sprintf("%d%s%d", front, password, back)},
		{"front(hex) + plaintext + back(hex)", fmt.Sprintf("%08x%s%08x", front, password, back)},
		{"FRONT(HEX) + plaintext + BACK(HEX)", fmt.Sprintf("%08X%s%08X", front, password, back)},
		{"back(dec) + plaintext + front(dec)", fmt.Sprintf("%d%s%d", back, password, front)},
	}
	
	for _, test := range tests {
		hash := fmt.Sprintf("%x", sha1.Sum([]byte(test.str)))
		if hash == clientSHA1 {
			fmt.Printf("✅ FOUND! %s\n", test.name)
			fmt.Printf("String: %s\n", test.str)
			fmt.Printf("SHA1:   %s\n\n", hash)
			
			fmt.Println("SOLUTION: Database harus store PLAINTEXT password, bukan MD5!")
			fmt.Println("UPDATE login SET password='test123' WHERE username='testlogin';")
			return
		}
	}
	
	fmt.Println("❌ Still no match with plaintext either!")
	fmt.Println("Client is using a completely different algorithm...")
}
