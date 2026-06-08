package model

import (
	"encoding/json"
	"testing"
)

func TestAppearanceJSONRoundTrip(t *testing.T) {
	a := Appearance{Hair: 3, HairColor: 7, Face: 1}
	b, err := json.Marshal(a)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got Appearance
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got != a {
		t.Errorf("round-trip Appearance: got %+v, mau %+v", got, a)
	}
}

func TestActorWrapsCharacter(t *testing.T) {
	c := &Character{ID: 42, Name: "Tester", MapID: 1, X: 10, Y: 20}
	act := &Actor{Character: c, CurX: 10, CurY: 20, Direction: 4}
	if act.Character.ID != 42 {
		t.Errorf("Actor tak membungkus Character dengan benar: %+v", act)
	}
	if act.CurX != 10 || act.CurY != 20 || act.Direction != 4 {
		t.Errorf("state live Actor salah: %+v", act)
	}
}
