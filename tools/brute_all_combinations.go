package main
import (
	"crypto/sha1"
	"encoding/binary"
	"fmt"
)

func main() {
	packetHex := []byte{0xf3, 0x17, 0xc4, 0x8f, 0x9e, 0x9d, 0x28, 0x64}
	clientSHA1 := "5105bac4a6c0271008ec993f0bce105b1324e81f"
	storedMD5 := "57b2f4c72fd9e904593453cfed3ef751"
	
	fmt.Println("=== Trying all possible front/back interpretations ===\n")
	
	// Try all offsets and endianness
	for offset := 0; offset <= 0; offset++ {
		if offset+8 > len(packetHex) {
			break
		}
		
		// Big-endian
		frontBE := binary.BigEndian.Uint32(packetHex[offset : offset+4])
		backBE := binary.BigEndian.Uint32(packetHex[offset+4 : offset+8])
		testCombination("BE", offset, frontBE, backBE, storedMD5, clientSHA1)
		
		// Little-endian
		frontLE := binary.LittleEndian.Uint32(packetHex[offset : offset+4])
		backLE := binary.LittleEndian.Uint32(packetHex[offset+4 : offset+8])
		testCombination("LE", offset, frontLE, backLE, storedMD5, clientSHA1)
		
		// Mixed: BE front, LE back
		testCombination("BE/LE", offset, frontBE, backLE, storedMD5, clientSHA1)
		
		// Mixed: LE front, BE back
		testCombination("LE/BE", offset, frontLE, backBE, storedMD5, clientSHA1)
	}
	
	fmt.Println("\n=== Trying swapped front/back ===")
	front := binary.BigEndian.Uint32(packetHex[0:4])
	back := binary.BigEndian.Uint32(packetHex[4:8])
	testCombination("Swapped BE", 0, back, front, storedMD5, clientSHA1)
}

func testCombination(name string, offset int, front, back uint32, md5Hex, expectedSHA1 string) {
	str := fmt.Sprintf("%d%s%d", front, md5Hex, back)
	sha := sha1.Sum([]byte(str))
	shaHex := fmt.Sprintf("%x", sha)
	
	if shaHex == expectedSHA1 {
		fmt.Printf("✓✓✓ MATCH FOUND! %s offset=%d\n", name, offset)
		fmt.Printf("    Front: %d (0x%08x)\n", front, front)
		fmt.Printf("    Back: %d (0x%08x)\n", back, back)
		fmt.Printf("    Challenge: %s\n", str)
	}
}
