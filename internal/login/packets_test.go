package login

import (
	"bytes"
	"encoding/hex"
	"testing"

	"lumeris-go/internal/model"
)

func TestBuildVersionACK(t *testing.T) {
	versionBytes := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}
	data := BuildVersionACK(0, versionBytes)
	// Body setelah ID = result uint16@0 + version 6 byte@2 = 8 byte (C# data[2..9]).
	if len(data) != 8 {
		t.Fatalf("VERSION_ACK panjang salah: %d", len(data))
	}
	if getUint16BE(data, 0) != 0 {
		t.Error("VERSION_ACK result bukan 0")
	}
	if !bytes.Equal(data[2:8], versionBytes) {
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
	// Capture klien asli: body 17 byte (paket total 19 byte termasuk ID 2 byte).
	if len(data) != 17 {
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
	data := BuildCharData([]*model.Character{char})
	// Saga18 array-4 body = 147 byte saat hanya slot 0 terisi nama "TestChar" (8 char).
	// nameMarker(1) + [9 slot0][1 slot1][1 slot2][1 slot3] = 13 nama,
	// lalu 20 blok field. Total tetap = capture 147 saat 2 nama (Larazeta+Recoil=14).
	// Di sini 1 nama 8-char => 13 byte nama, body = 13 + 134 = 147 - (14-8) = 141.
	wantLen := 1 + (1 + 8) + 1 + 1 + 1 + // names: marker + slot0(len+8) + 3 empty
		(1 + 4) + // Race
		(1 + 4) + // Form
		(1 + 4) + // Gender
		(1 + 8) + // HairStyle (2B×4)
		(1 + 4) + // HairColor
		(1 + 8) + // Wig (2B×4)
		(1 + 4) + // Exist
		(1 + 8) + // Face (2B×4)
		(1 + 4) + // Rebirth
		(1 + 4) + // Tail
		(1 + 4) + // Wing
		(1 + 4) + // WingColor
		(1 + 4) + // Job
		(1 + 16) + // Map (4B×4)
		(1 + 4) + // Lv
		(1 + 4) + // Job1
		(1 + 8) + // Quest (2B×4)
		(1 + 4) + // Job2X
		(1 + 4) + // Job2T
		(1 + 4) // Job3
	if len(data) != wantLen {
		t.Fatalf("CHAR_DATA panjang salah: got %d, want %d", len(data), wantLen)
	}
	// nameMarker harus 0x04
	if data[0] != 0x04 {
		t.Errorf("name marker = %d, harus 4", data[0])
	}
	// Slot0 nama: len=8, "TestChar"
	if data[1] != 8 || string(data[2:10]) != "TestChar" {
		t.Errorf("nama slot0 salah: len=%d %q", data[1], string(data[2:10]))
	}
	// Slot 1-3 kosong (len 0)
	if data[10] != 0 || data[11] != 0 || data[12] != 0 {
		t.Error("slot kosong harus len 0")
	}
}

func TestBuildCharEquip(t *testing.T) {
	data := BuildCharEquip()
	// Saga18: 4 slot × [marker 0x0D][13 uint32] = 4×53 = 212 byte.
	if len(data) != 212 {
		t.Fatalf("CHAR_EQUIP panjang salah: %d", len(data))
	}
	// Marker 0x0D di offset 0, 53, 106, 159
	if data[0] != 0x0D || data[53] != 0x0D || data[106] != 0x0D || data[159] != 0x0D {
		t.Error("CHAR_EQUIP marker 0x0D salah")
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
	// Wire format nyata (dari capture 63-byte): TANPA gap antara username & password.
	// uLen(termasuk \0), user, pLen(termasuk \0), pass(40-char hex), MAC 6 byte.
	// Pakai password hex 40-char (SHA1) seperti yang dikirim klien asli.
	passHex := "0123456789abcdef0123456789abcdef01234567" // 40 char hex
	data := make([]byte, 0, 1+5+1+len(passHex)+1+6)
	data = append(data, 5)                  // uLen ("test" + \0)
	data = append(data, []byte("test\x00")...)
	data = append(data, byte(len(passHex)+1)) // pLen (hex + \0)
	data = append(data, []byte(passHex)...)
	data = append(data, 0) // null terminator password
	mac := []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}
	data = append(data, mac...)

	parsed, err := ParseLogin(data)
	if err != nil {
		t.Fatalf("ParseLogin error: %v", err)
	}
	if parsed.Username != "test" {
		t.Errorf("Username salah: %q", parsed.Username)
	}
	// Password di-decode dari hex jadi 20 byte raw.
	wantPass, _ := hex.DecodeString(passHex)
	if !bytes.Equal(parsed.Password, wantPass) {
		t.Errorf("Password salah: got %02x, want %02x", parsed.Password, wantPass)
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
