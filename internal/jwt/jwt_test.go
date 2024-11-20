package jwt

import (
	"encoding/json"
	"testing"
)

func TestDuplicatedJSONKeyShouldReturnLexicallyLast(t *testing.T) {
	r := make(map[string]int)
	json.Unmarshal([]byte("{\"key\":1,\"key\":2}"), &r)
	val, ok := r["key"]
	if !ok {
		t.Fatal("JSON key was discarded")
	}
	if val != 2 {
		t.Fatal("JSON doesn't work as expect")
	}
}
