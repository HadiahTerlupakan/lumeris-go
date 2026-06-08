package main
import "fmt"

func main() {
	versionBytes := []byte{0x03, 0xE8, 0x01, 0x5F, 0x37, 0x71}
	
	fmt.Println("=== DECODE CLIENT VERSION ===\n")
	fmt.Printf("Raw bytes: %02X %02X %02X %02X %02X %02X\n\n", 
		versionBytes[0], versionBytes[1], versionBytes[2], 
		versionBytes[3], versionBytes[4], versionBytes[5])
	
	// Try different interpretations
	fmt.Println("Possible interpretations:")
	fmt.Printf("1. As 3 uint16 (BE): %d.%d.%d\n", 
		uint16(versionBytes[0])<<8|uint16(versionBytes[1]),
		uint16(versionBytes[2])<<8|uint16(versionBytes[3]),
		uint16(versionBytes[4])<<8|uint16(versionBytes[5]))
	
	fmt.Printf("2. As decimal bytes: %d.%d.%d.%d.%d.%d\n",
		versionBytes[0], versionBytes[1], versionBytes[2],
		versionBytes[3], versionBytes[4], versionBytes[5])
	
	fmt.Printf("3. As hex string: %02X%02X%02X%02X%02X%02X\n",
		versionBytes[0], versionBytes[1], versionBytes[2],
		versionBytes[3], versionBytes[4], versionBytes[5])
	
	fmt.Println("\nNekogameECO capture juga punya version ini - artinya client standard ECO.")
	fmt.Println("Problem bukan di client version, tapi di challenge algorithm implementation!")
}
