package main

import (
	"crypto/md5"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

func main() {
	// Data dari log:
	front := uint32(0x4bb6b365)
	back := uint32(0xd9a2302c)
	clientSHA1 := "cd18578fd3f1d3f187efab55c905507e9331255f"

	fmt.Println("=== Brute Force Search ===")
	fmt.Println("Trying common passwords to find which one produces the client SHA1...")

	// Expanded password list
	passwords := []string{
		"dummy", "test", "password", "123456", "admin", "root",
		"user", "guest", "demo", "test123", "password123",
		"a", "aa", "aaa", "aaaa", "aaaaa",
		"1", "12", "123", "1234", "12345", "123456", "1234567",
		// Tambahkan password dengan MD5 yang mirip dengan yang tersimpan
	}

	// Juga test dengan MD5 yang tersimpan langsung sebagai "password"
	storedMD5 := "851fdee206c1eec10cee5ec8e8962af2"
	passwords = append(passwords, storedMD5) // Test jika password adalah MD5 string itu sendiri

	found := false
	for _, plaintext := range passwords {
		h := md5.Sum([]byte(plaintext))
		calculatedMD5 := hex.EncodeToString(h[:])

		// Test uppercase ASCII format
		buf := make([]byte, 4+32+4)
		binary.BigEndian.PutUint32(buf[0:4], front)
		md5Upper := strings.ToUpper(calculatedMD5)
		copy(buf[4:36], []byte(md5Upper))
		binary.BigEndian.PutUint32(buf[36:40], back)
		sha1Result := sha1.Sum(buf)
		sha1Hex := hex.EncodeToString(sha1Result[:])

		if sha1Hex == clientSHA1 {
			fmt.Printf("\n✓✓✓ FOUND! Password: '%s'\n", plaintext)
			fmt.Printf("    MD5: %s\n", calculatedMD5)
			fmt.Printf("    SHA1: %s\n", sha1Hex)
			found = true
			break
		}

		// Test lowercase ASCII format
		buf2 := make([]byte, 4+32+4)
		binary.BigEndian.PutUint32(buf2[0:4], front)
		md5Lower := strings.ToLower(calculatedMD5)
		copy(buf2[4:36], []byte(md5Lower))
		binary.BigEndian.PutUint32(buf2[36:40], back)
		sha1Result2 := sha1.Sum(buf2)
		sha1Hex2 := hex.EncodeToString(sha1Result2[:])

		if sha1Hex2 == clientSHA1 {
			fmt.Printf("\n✓✓✓ FOUND! Password: '%s' (lowercase MD5)\n", plaintext)
			fmt.Printf("    MD5: %s\n", calculatedMD5)
			fmt.Printf("    SHA1: %s\n", sha1Hex2)
			found = true
			break
		}

		// Test raw bytes format
		buf3 := make([]byte, 4+16+4)
		binary.BigEndian.PutUint32(buf3[0:4], front)
		md5bytes, _ := hex.DecodeString(calculatedMD5)
		copy(buf3[4:20], md5bytes)
		binary.BigEndian.PutUint32(buf3[20:24], back)
		sha1Result3 := sha1.Sum(buf3)
		sha1Hex3 := hex.EncodeToString(sha1Result3[:])

		if sha1Hex3 == clientSHA1 {
			fmt.Printf("\n✓✓✓ FOUND! Password: '%s' (raw bytes MD5)\n", plaintext)
			fmt.Printf("    MD5: %s\n", calculatedMD5)
			fmt.Printf("    SHA1: %s\n", sha1Hex3)
			found = true
			break
		}
	}

	if !found {
		fmt.Println("\n✗ Password not found in common list")
		fmt.Println("\nPossibility: The stored MD5 hash is for a different password than what client used")
		fmt.Println("             OR the challenge format is different than expected")

		// Coba analisa apa yang client kirim
		fmt.Println("\n=== Analysis ===")
		fmt.Println("What if we reverse: What MD5 would produce that SHA1?")

		// Try to extract MD5 from SHA1 by trying all possible MD5 hashes (infeasible)
		// Instead, let's check the actual registration
		fmt.Println("\nNext steps:")
		fmt.Println("1. Check what password was used when registering 'dummy' account")
		fmt.Println("2. Verify the stored MD5 in database matches MD5(password)")
		fmt.Println("3. Test login with that exact password")
	}
}
