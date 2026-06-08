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
	// Field tambahan untuk char-list packet (Plan 4)
	Race           byte // 0=Emilia, 1=Titania, 2=DEM, 3=Dominion
	Gender         byte // 0=Male, 1=Female
	Form           byte // Job-specific form/class variant
	Wig            byte // 0xFF = no wig
	Face           int  // Face ID (int untuk konsistensi dengan packet)
	QuestRemaining int  // Quest slots remaining (default 3)
	JobLevel1      int  // Level job pertama
	JobLevel2X     int  // Level job kedua (X path)
	JobLevel2T     int  // Level job kedua (T path)
	JobLevel3      int  // Level job ketiga
	Rebirth        bool // True jika karakter rebirth
}
