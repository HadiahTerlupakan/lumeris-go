package login

import (
	"bytes"
	"testing"

	"lumeris-go/internal/model"
)

func TestBuildVersionACK(t *testing.T) {
	versionBytes := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}
	data := BuildVersionACK(0, versionBytes)
	if len(data) != 10 {
		t.Fatalf("VERSION_ACK panjang salah: %d", len(data))
	}
	if getUint16BE(data, 0) != 0 {
		t.Error("VERSION_ACK result bukan 0")
	}
	if !bytes.Equal(data[4:10], versionBytes) {
		t.Error("VERSION_ACK version bytes salah")
	}
}

func TestBuildLoginAllowed(t *testing.T) {
	front := uint32(0x12345678)
	back := uint32(0x9ABCDEF0)
	data := BuildLoginAllowed(front, back)
	if len(data) != 8 {
		t.Fatalf("LOGIN_ALLOWED panjang salah: %d", len(data))
	}
	if getUint32BE(data, 0) != front {
		t.Errorf("front salah: got %08x, want %08x", getUint32BE(data, 0), front)
	}
	if getUint32BE(data, 4) != back {
		t.Errorf("back salah: got %08x, want %08x", getUint32BE(data, 4), back)
	}
}

func TestBuildLoginACK(t *testing.T) {
	data := BuildLoginACK(LOGIN_OK, 42)
	if len(data) != 16 {
		t.Fatalf("LOGIN_ACK panjang salah: %d", len(data))
	}
	if getUint32BE(data, 0) != LOGIN_OK {
		t.Error("LOGIN_ACK result bukan OK")
	}
	if getUint32BE(data, 4) != 42 {
		t.Error("LOGIN_ACK accountID salah")
	}
}

func TestBuildCharData(t *testing.T) {
	char := &model.Character{
		ID:             123,
		Slot:           0,
		Name:           "TestChar",
		Race:           1,
		Gender:         0,
		Job:            1,
		Level:          5,
		HP:             150,
		MaxHP:          150,
		SP:             100,
		MaxSP:          100,
		Str:            10,
		Dex:            10,
		Int:            10,
		Vit:            10,
		Agi:            10,
		Mnd:            10,
		Appearance:     model.Appearance{Hair: 3, HairColor: 7, Face: 1},
		Face:           1,
		Form:           0,
		Wig:            255,
		MapID:          1,
		X:              100,
		Y:              200,
		QuestRemaining: 3,
		JobLevel1:      5,
	}
	data := BuildCharData(char)
	if len(data) != 131 {
		t.Fatalf("CHAR_DATA panjang salah: %d", len(data))
	}
	// Verifikasi field kunci
	if getUint32BE(data, 0) != 123 {
		t.Error("CharID salah")
	}
	if data[4] != 0 {
		t.Error("Slot salah")
	}
	if string(bytes.TrimRight(data[5:37], "\x00")) != "TestChar" {
		t.Errorf("Name salah: %q", string(bytes.TrimRight(data[5:37], "\x00")))
	}
	if data[37] != 1 {
		t.Error("Race salah")
	}
	if data[39] != 1 {
		t.Error("Job salah")
	}
	if data[40] != 5 {
		t.Error("Level salah")
	}
}

func TestBuildCharEquip(t *testing.T) {
	data := BuildCharEquip()
	if len(data) != 230 {
		t.Fatalf("CHAR_EQUIP panjang salah: %d", len(data))
	}
	// Verifikasi marker 0x0E
	if data[0] != 0x0E || data[57] != 0x0E || data[114] != 0x0E || data[171] != 0x0E {
		t.Error("CHAR_EQUIP marker 0x0E salah")
	}
}

func TestBuildSendToMapServer(t *testing.T) {
	data := BuildSendToMapServer(1, "127.0.0.1", 12024)
	// Layout: serverID(1) + ipLen(1) + ip(9) + port(4) = 15 byte
	if len(data) != 15 {
		t.Fatalf("SEND_TO_MAP_SERVER panjang salah: %d", len(data))
	}
	if data[0] != 1 {
		t.Error("serverID salah")
	}
	if data[1] != 9 {
		t.Error("ipLen salah")
	}
	if string(data[2:11]) != "127.0.0.1" {
		t.Errorf("IP salah: %q", string(data[2:11]))
	}
	if getUint32BE(data, 11) != 12024 {
		t.Errorf("Port salah: %d", getUint32BE(data, 11))
	}
}

func TestParseLogin(t *testing.T) {
	// Simulasi CSMG_LOGIN packet:
	// uLen=5("test"+\0), user="test", gap 1 byte, pLen=21(20 byte SHA1+\0), pass=20 byte, MAC=6 byte
	data := make([]byte, 1+5+1+1+21+6)
	offset := 0
	// Username "test"
	data[offset] = 5 // uLen (termasuk \0)
	offset++
	copy(data[offset:], []byte("test\x00"))
	offset += 5
	// Gap (ASIMETRI)
	offset++ // ini yang penting!
	// Password (20 byte SHA1)
	data[offset] = 21 // pLen (20 + \0)
	offset++
	pass := []byte("01234567890123456789") // 20 byte dummy
	copy(data[offset:], pass)
	data[offset+20] = 0 // null terminator
	offset += 21
	// MAC 6 byte
	mac := []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}
	copy(data[offset:], mac)

	parsed, err := ParseLogin(data)
	if err != nil {
		t.Fatalf("ParseLogin error: %v", err)
	}
	if parsed.Username != "test" {
		t.Errorf("Username salah: %q", parsed.Username)
	}
	if !bytes.Equal(parsed.Password, pass) {
		t.Error("Password salah")
	}
	if !bytes.Equal(parsed.MAC, mac) {
		t.Error("MAC salah")
	}
}

func TestParseCharCreate(t *testing.T) {
	// Slot=0, name="Hero\0" (len=5), Race=1, Gender=0, gap, Hair=3, HairColor=7, Face=1(uint16)
	data := []byte{
		0,                   // Slot
		5,                   // nameLen
		'H', 'e', 'r', 'o', 0, // name
		1,    // Race
		0,    // Gender
		0xFF, // gap
		3,    // HairStyle
		7,    // HairColor
		0, 1, // Face uint16 BE = 1
	}
	parsed, err := ParseCharCreate(data)
	if err != nil {
		t.Fatalf("ParseCharCreate error: %v", err)
	}
	if parsed.Slot != 0 {
		t.Error("Slot salah")
	}
	if parsed.Name != "Hero" {
		t.Errorf("Name salah: %q", parsed.Name)
	}
	if parsed.Race != 1 || parsed.Gender != 0 {
		t.Error("Race/Gender salah")
	}
	if parsed.HairStyle != 3 || parsed.HairColor != 7 {
		t.Error("Hair salah")
	}
	if parsed.Face != 1 {
		t.Error("Face salah")
	}
}

func TestParseCharDelete(t *testing.T) {
	// Slot=1, pwLen=5("0000"+\0), deletePass="0000"
	data := []byte{
		1,                      // Slot
		5,                      // pwLen
		'0', '0', '0', '0', 0, // deletePass
	}
	parsed, err := ParseCharDelete(data)
	if err != nil {
		t.Fatalf("ParseCharDelete error: %v", err)
	}
	if parsed.Slot != 1 {
		t.Error("Slot salah")
	}
	if parsed.DeletePassword != "0000" {
		t.Errorf("DeletePassword salah: %q", parsed.DeletePassword)
	}
}

func TestParseCharSelect(t *testing.T) {
	data := []byte{2} // Slot=2
	parsed, err := ParseCharSelect(data)
	if err != nil {
		t.Fatalf("ParseCharSelect error: %v", err)
	}
	if parsed.Slot != 2 {
		t.Error("Slot salah")
	}
}
