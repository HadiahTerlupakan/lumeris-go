package main
import "fmt"
func main() {
	// Dari log: "challenge sent (front=19eaa3d1, back=617a53ee)"
	frontHex := uint32(0x19eaa3d1)
	backHex := uint32(0x617a53ee)
	
	fmt.Printf("Front hex: 0x%08x = %d\n", frontHex, frontHex)
	fmt.Printf("Back hex: 0x%08x = %d\n", backHex, backHex)
	fmt.Println()
	
	// Dari log verification: front=434807761, back=1635406830
	fmt.Printf("Expected from log: front=%d, back=%d\n", 434807761, 1635406830)
	fmt.Printf("Match: %v\n", frontHex == 434807761 && backHex == 1635406830)
}
