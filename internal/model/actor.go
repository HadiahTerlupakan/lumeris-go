package model

// Actor adalah entitas hidup di peta: membungkus data Character + state runtime.
// Field live (posisi sekarang, arah) diisi/dipakai saat fase Map (Plan 5).
// Pemisahan Character (data tersimpan) vs Actor (runtime) disengaja — Actor inilah
// unit aktor saat fase actor-model nanti.
type Actor struct {
	*Character
	CurX, CurY int // posisi runtime (bisa beda dari Character.X/Y saat bergerak)
	Direction  int // arah hadap
}
