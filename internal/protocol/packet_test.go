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
