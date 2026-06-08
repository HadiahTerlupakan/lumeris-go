package main
import (
	"crypto/sha1"
	"fmt"
)

func main() {
	// From log line 13, 16-19
	front := uint32(1496071116)  // 0x592C3BCC
	back := uint32(3854248468)   // 0xE5BB2A14
	md5Hash := "cc03e747a6afbbcbf8be7668acfebee5"
	clientSHA1 := "411b49e106bcc0483309e86268c5121c7b7a45e0"
	
	fmt.Println("=== REVERSE ENGINEER CLIENT CHALLENGE FORMAT ===\n")
	fmt.Printf("Front: %d (0x%08X)\n", front, front)
	fmt.Printf("Back:  %d (0x%08X)\n", back, back)
	fmt.Printf("MD5:   %s\n", md5Hash)
	fmt.Printf("Target Client SHA1: %s\n\n", clientSHA1)
	
	tests := []struct{
		name string
		str  string
	}{
		// Hex formats (lowercase)
		{"hex(lower) + md5 + hex(lower)", fmt.Sprintf("%08x%s%08x", front, md5Hash, back)},
		{"hex(lower) + md5 + hex(lower) NO PADDING", fmt.Sprintf("%x%s%x", front, md5Hash, back)},
		
		// Hex formats (UPPERCASE)
		{"HEX(UPPER) + md5 + HEX(UPPER)", fmt.Sprintf("%08X%s%08X", front, md5Hash, back)},
		{"HEX(UPPER) + MD5(UPPER) + HEX(UPPER)", fmt.Sprintf("%08X%s%08X", front, "CC03E747A6AFBBCBF8BE7668ACFEBEE5", back)},
		
		// Reversed order
		{"back(hex) + md5 + front(hex)", fmt.Sprintf("%08x%s%08x", back, md5Hash, front)},
		{"back(dec) + md5 + front(dec)", fmt.Sprintf("%d%s%d", back, md5Hash, front)},
		
		// With separators
		{"hex-md5-hex (dash)", fmt.Sprintf("%08x-%s-%08x", front, md5Hash, back)},
		{"hex md5 hex (space)", fmt.Sprintf("%08x %s %08x", front, md5Hash, back)},
	}
	
	for i, test := range tests {
		hash := fmt.Sprintf("%x", sha1.Sum([]byte(test.str)))
		if hash == clientSHA1 {
			fmt.Printf("✅ MATCH FOUND! Test #%d\n", i+1)
			fmt.Printf("Format: %s\n", test.name)
			fmt.Printf("String: %s\n", test.str)
			fmt.Printf("SHA1:   %s\n", hash)
			return
		}
	}
	
	fmt.Println("❌ No match found!")
	fmt.Println("\nClient is using a DIFFERENT challenge algorithm than we expected!")
}
