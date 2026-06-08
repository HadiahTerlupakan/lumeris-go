package main
import (
	"crypto/sha1"
	"fmt"
)

func main() {
	// Attempt 1
	front1 := uint32(889449806)   // 0x3503ED4E
	back1 := uint32(2182696076)   // 0x82194C8C
	client1 := "09d7e3afb5a81edef46f7e3258b1d26941fc27b0"
	
	// Attempt 2
	front2 := uint32(3574088812)  // 0xD508446C
	back2 := uint32(375131406)    // 0x165C0D0E
	client2 := "8cacfb31f81b8c2d6fcd2dacbcb53d9e680e0c1a"
	
	// Attempt 3
	front3 := uint32(1581453553)  // 0x5E4310F1
	back3 := uint32(3729531152)   // 0xDE4C2110
	client3 := "45a06ce09f4f21c3d5acb25fba116b7efed9d59f"
	
	md5 := "482c811da5d5b4bc6d497ffa98491e38"
	password := "password123"
	
	fmt.Println("=== ANALYZE 3 ATTEMPTS TO FIND PATTERN ===\n")
	
	// Test if client uses HEX format instead of decimal
	str1_hex := fmt.Sprintf("%08x%s%08x", front1, md5, back1)
	hash1_hex := fmt.Sprintf("%x", sha1.Sum([]byte(str1_hex)))
	
	str2_hex := fmt.Sprintf("%08x%s%08x", front2, md5, back2)
	hash2_hex := fmt.Sprintf("%x", sha1.Sum([]byte(str2_hex)))
	
	str3_hex := fmt.Sprintf("%08x%s%08x", front3, md5, back3)
	hash3_hex := fmt.Sprintf("%x", sha1.Sum([]byte(str3_hex)))
	
	fmt.Println("Test: Hex format (lowercase)")
	fmt.Printf("Attempt 1: %v\n", hash1_hex == client1)
	fmt.Printf("Attempt 2: %v\n", hash2_hex == client2)
	fmt.Printf("Attempt 3: %v\n", hash3_hex == client3)
	
	if hash1_hex == client1 && hash2_hex == client2 && hash3_hex == client3 {
		fmt.Println("\n✅ FOUND! Client uses HEX format (lowercase)!")
		fmt.Println("Format: front(hex08) + md5 + back(hex08)")
		fmt.Printf("Example: %s\n", str1_hex)
		return
	}
	
	// Test UPPERCASE hex
	str1_upper := fmt.Sprintf("%08X%s%08X", front1, "482C811DA5D5B4BC6D497FFA98491E38", back1)
	hash1_upper := fmt.Sprintf("%x", sha1.Sum([]byte(str1_upper)))
	
	fmt.Println("\nTest: Hex format (UPPERCASE)")
	fmt.Printf("Attempt 1: %v\n", hash1_upper == client1)
	
	if hash1_upper == client1 {
		fmt.Println("\n✅ FOUND! Client uses HEX UPPERCASE!")
		return
	}
	
	// Test plaintext password
	str1_plain := fmt.Sprintf("%08x%s%08x", front1, password, back1)
	hash1_plain := fmt.Sprintf("%x", sha1.Sum([]byte(str1_plain)))
	
	fmt.Println("\nTest: Plaintext password (hex format)")
	fmt.Printf("Attempt 1: %v\n", hash1_plain == client1)
	
	if hash1_plain == client1 {
		fmt.Println("\n✅ FOUND! Client uses plaintext password with hex front/back!")
		return
	}
	
	fmt.Println("\n❌ Still cannot find the algorithm...")
	fmt.Println("Client menggunakan protokol yang SANGAT berbeda dari C# SagaECO!")
}
