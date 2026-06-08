//go:build ignore

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
	// Password yang ditemukan
	password := "dummy123"
	
	// Data dari log
	front := uint32(0x4bb6b365)
	back := uint32(0xd9a2302c)
	clientSHA1 := "cd18578fd3f1d3f187efab55c905507e9331255f"
	
	fmt.Printf("=== Verifying password: '%s' ===

", password)
	
	// Calculate MD5
	h := md5.Sum([]byte(password))
	calculatedMD5 := hex.EncodeToString(h[:])
	fmt.Printf("MD5: %s
", calculatedMD5)
	
	// Build challenge buffer (uppercase MD5)
	buf := make([]byte, 4+32+4)
	binary.BigEndian.PutUint32(buf[0:4], front)
	md5Upper := strings.ToUpper(calculatedMD5)
	copy(buf[4:36], []byte(md5Upper))
	binary.BigEndian.PutUint32(buf[36:40], back)
	
	// Calculate SHA1
	sha1Result := sha1.Sum(buf)
	sha1Hex := hex.EncodeToString(sha1Result[:])
	
	fmt.Printf("Buffer: %02x
", buf)
	fmt.Printf("Expected SHA1: %s
", sha1Hex)
	fmt.Printf("Client SHA1:   %s
", clientSHA1)
	
	if sha1Hex == clientSHA1 {
		fmt.Println("
✓✓✓ MATCH! Password 'dummy123' is correct!")
		fmt.Println("
The login should work now if you use password 'dummy123'")
	} else {
		fmt.Println("
✗ No match - there's still an issue")
	}
}
