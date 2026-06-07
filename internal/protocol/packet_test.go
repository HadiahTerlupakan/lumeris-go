package protocol

import "testing"

func TestNewPacketOffsetIs4(t *testing.T) {
	p := NewPacket(10)
	if p.Offset != 4 {
		t.Errorf("Offset awal = %d, mau 4", p.Offset)
	}
	if len(p.Data) != 10 {
		t.Errorf("len(Data) = %d, mau 10", len(p.Data))
	}
}

func TestPutGetByte(t *testing.T) {
	p := NewPacket(8)
	p.PutByteAt(0xAB, 4)
	if got := p.GetByteAt(4); got != 0xAB {
		t.Errorf("GetByteAt(4) = %#x, mau 0xab", got)
	}
	if p.Offset != 5 {
		t.Errorf("Offset setelah PutByteAt = %d, mau 5", p.Offset)
	}
}

func TestPutUShortBigEndian(t *testing.T) {
	p := NewPacket(8)
	p.PutUShortAt(0x1234, 4)
	// big-endian: byte tinggi dulu
	if p.Data[4] != 0x12 || p.Data[5] != 0x34 {
		t.Errorf("bytes = %#x %#x, mau 0x12 0x34", p.Data[4], p.Data[5])
	}
	if got := p.GetUShortAt(4); got != 0x1234 {
		t.Errorf("GetUShortAt = %#x, mau 0x1234", got)
	}
}

func TestPutUIntBigEndian(t *testing.T) {
	p := NewPacket(12)
	p.PutUIntAt(0x11223344, 4)
	if p.Data[4] != 0x11 || p.Data[5] != 0x22 || p.Data[6] != 0x33 || p.Data[7] != 0x44 {
		t.Errorf("bytes = %#x %#x %#x %#x, mau 11 22 33 44", p.Data[4], p.Data[5], p.Data[6], p.Data[7])
	}
	if got := p.GetUIntAt(4); got != 0x11223344 {
		t.Errorf("GetUIntAt = %#x, mau 0x11223344", got)
	}
}

func TestPutFloatLittleEndian(t *testing.T) {
	// PENTING: float TIDAK dibalik (little-endian), beda dari integer.
	p := NewPacket(12)
	p.PutFloatAt(1.0, 4) // IEEE754 1.0f = 0x3F800000; LE byte = 00 00 80 3F
	if p.Data[4] != 0x00 || p.Data[5] != 0x00 || p.Data[6] != 0x80 || p.Data[7] != 0x3F {
		t.Errorf("bytes = %#x %#x %#x %#x, mau 00 00 80 3F (little-endian)", p.Data[4], p.Data[5], p.Data[6], p.Data[7])
	}
	if got := p.GetFloatAt(4); got != 1.0 {
		t.Errorf("GetFloatAt = %v, mau 1.0", got)
	}
}
