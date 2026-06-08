package main
import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
)

func main() {
	// LOGIN_ALLOWED dari NekogameECO: 4D 4C FA F4 44 41 03 56
	data, _ := hex.DecodeString("4D4CFAF444410356")
	
	// Parse sebagai 2 uint32 big-endian
	front := uint32(data[0])<<24 | uint32(data[1])<<16 | uint32(data[2])<<8 | uint32(data[3])
	back := uint32(data[4])<<24 | uint32(data[5])<<16 | uint32(data[6])<<8 | uint32(data[7])
	
	fmt.Printf("Front word: 0x%08X (%d)\n", front, front)
	fmt.Printf("Back word:  0x%08X (%d)\n\n", back, back)
	
	// CSMG_LOGIN response: 29 64 33 66 63 36 37 63 35 ... (SHA1 hash)
	// Skip 0x29 (length byte), ambil 40 bytes hex string
	clientResponse := "d3fc67c57e1fe65b37773a49eb02082baabf24a6"
	fmt.Printf("Client SHA1: %s\n\n", clientResponse)
	
	// Assume password MD5 for "larazeta" di NekogameECO
	// Kita tidak tahu, jadi coba dengan format berbeda
	
	fmt.Println("=== Testing Challenge Formats ===\n")
	
	// Kita tidak punya MD5 password NekogameECO, tapi kita bisa test dengan user9999
	// Dari log kita:
	// Front: 0x7445C660 (1950729824)
	// Back:  0xA3DB64DC (2749064412)
	// MD5:   57b2f4c72fd9e904593453cfed3ef751
	// Client SHA1: 9b6bff95eef22dde49f7814681c883e0bae6f00a
	
	ourFront := uint32(0x7445C660)
	ourBack := uint32(0xA3DB64DC)
	ourMD5 := "57b2f4c72fd9e904593453cfed3ef751"
	ourClientSHA1 := "9b6bff95eef22dde49f7814681c883e0bae6f00a"
	
	fmt.Println("OUR SERVER TEST:")
	fmt.Printf("Front: 0x%08X (%d)\n", ourFront, ourFront)
	fmt.Printf("Back:  0x%08X (%d)\n", ourBack, ourBack)
	fmt.Printf("MD5:   %s\n", ourMD5)
	fmt.Printf("Client SHA1: %s\n\n", ourClientSHA1)
	
	// Try: front(hex lowercase) + md5 + back(hex lowercase)
	str1 := fmt.Sprintf("%08x%s%08x", ourFront, ourMD5, ourBack)
	hash1 := fmt.Sprintf("%x", sha1.Sum([]byte(str1)))
	fmt.Printf("1. Format: front(hex) + md5 + back(hex)\n")
	fmt.Printf("   String: %s\n", str1)
	fmt.Printf("   SHA1:   %s\n", hash1)
	fmt.Printf("   Match:  %v\n\n", hash1 == ourClientSHA1)
	
	// WAIT - maybe client sends MD5 of password, not stored MD5!
	// Let me check if client does: front(dec) + MD5(password_plaintext) + back(dec)
	fmt.Println("2. HYPOTHESIS: Client mungkin kirim MD5 dari plaintext password!")
	fmt.Println("   Coba: SHA1(front_hex + md5_plaintext + back_hex)")
	
	// MD5 dari "pass9999"
	// Kita sudah tahu: MD5("pass9999") = 57b2f4c72fd9e904593453cfed3ef751
	// Tapi mungkin client hash ulang atau pakai format lain?
}
