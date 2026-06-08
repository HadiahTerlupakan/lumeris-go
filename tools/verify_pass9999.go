package main
import (
	"crypto/md5"
	"crypto/sha1"
	"fmt"
)
func main() {
	pw := "pass9999"
	hash := md5.Sum([]byte(pw))
	md5Hex := fmt.Sprintf("%x", hash)
	
	fmt.Printf("Password: %s\n", pw)
	fmt.Printf("MD5: %s\n", md5Hex)
	fmt.Println()
	
	// Test dengan front/back dari log pertama
	front := uint32(434807761)
	back := uint32(1635406830)
	str := fmt.Sprintf("%d%s%d", front, md5Hex, back)
	expected := sha1.Sum([]byte(str))
	
	fmt.Printf("Front: %d (0x%08x)\n", front, front)
	fmt.Printf("Back: %d (0x%08x)\n", back, back)
	fmt.Printf("Challenge string: %s\n", str)
	fmt.Printf("Expected SHA1: %x\n", expected)
	fmt.Printf("Client sent: 0b92e155aa6338411801251450f62e375a4bd3e9\n")
}
