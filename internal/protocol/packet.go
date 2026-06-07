package protocol

// Packet adalah unit serialisasi wire ECO: SIZE(2) | ID(2) | DATA.
// Integer multi-byte big-endian; float little-endian (lihat PutFloat).
// Offset awal = 4 (lewati 2 byte size + 2 byte id), replika SagaLib/Packet.cs.
type Packet struct {
	Data   []byte
	Offset int
}

// NewPacket membuat packet dengan Data sepanjang length, Offset di 4.
func NewPacket(length int) *Packet {
	return &Packet{Data: make([]byte, length), Offset: 4}
}

// ensureLen memperbesar Data agar minimal sepanjang n.
func (p *Packet) ensureLen(n int) {
	if len(p.Data) < n {
		buf := make([]byte, n)
		copy(buf, p.Data)
		p.Data = buf
	}
}

// GetByteAt membaca 1 byte di index dan menyetel Offset ke index+1.
func (p *Packet) GetByteAt(index int) byte {
	p.Offset = index + 1
	return p.Data[index]
}

// PutByteAt menulis 1 byte di index dan menyetel Offset ke index+1.
func (p *Packet) PutByteAt(b byte, index int) {
	p.ensureLen(index + 1)
	p.Data[index] = b
	p.Offset = index + 1
}
