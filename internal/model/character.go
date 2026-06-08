package model

// Appearance menyimpan tampilan karakter (disimpan sebagai jsonb di DB).
type Appearance struct {
	Hair      int `json:"hair"`
	HairColor int `json:"hair_color"`
	Face      int `json:"face"`
}

// Character adalah data karakter tersimpan (lihat tabel characters).
type Character struct {
	ID         int64
	AccountID  int64
	Slot       int
	Name       string
	Job        int
	Level      int
	MapID      int
	X, Y       int
	HP, MaxHP  int
	SP, MaxSP  int
	Str        int
	Dex        int
	Int        int
	Vit        int
	Agi        int
	Mnd        int
	Appearance Appearance
}
