package main
import (
	"crypto/sha1"
	"encoding/binary"
	"fmt"
)

func main() {
	// Data dari log attempt 1
	packetHex := []byte{0xf3, 0x17, 0xc4, 0x8f, 0x9e, 0x9d, 0x28, 0x64}
	clientSHA1 := "5105bac4a6c0271008ec993f0bce105b1324e81f"
	storedMD5 := "57b2f4c72fd9e904593453cfed3ef751"
	
	// Parse front/back
	front := binary.BigEndian.Uint32(packetHex[0:4])
	back := binary.BigEndian.Uint32(packetHex[4:8])
	
	fmt.Printf("Packet: %02x\n", packetHex)
	fmt.Printf("Front: %d (0x%08x)\n", front, front)
	fmt.Printf("Back: %d (0x%08x)\n\n", back, back)
	
	// Test dengan MD5 yang benar
	str := fmt.Sprintf("%d%s%d", front, storedMD5, back)
	sha := sha1.Sum([]byte(str))
	shaHex := fmt.Sprintf("%x", sha)
	
	fmt.Printf("Challenge string: %s\n", str)
	fmt.Printf("Our SHA1: %s\n", shaHex)
	fmt.Printf("Client SHA1: %s\n", clientSHA1)
	fmt.Printf("Match: %v\n", shaHex == clientSHA1)
}
