package adapters

import (
	"context"
	"encoding/json"
	"os"

	"github.com/G5Olivieri/luau/jose/jwk"
	"github.com/G5Olivieri/luau/kms"
)

type keyJson struct {
	Alg    jwk.KeyAlg   `json:"alg"`
	Type   jwk.KeyType  `json:"typ"`
	KeyOps []jwk.KeyOps `json:"key_ops"`
	Use    jwk.KeyUse   `json:"use"`
}

type keyJsonFile struct {
	Keys []*keyJson `json:"keys"`
}

type createdKeyJson struct {
	ID  string `json:"id"`
	Alg string `json:"alg"`
}

type createdKeysJson struct {
	Keys []createdKeyJson `json:"keys"`
}

func LoadFromJson(impl kms.KMS, keysPath string) (string, error) {
	initialKeysContent, err := os.ReadFile(keysPath)
	if err != nil {
		return "", nil
	}

	var keyJson keyJsonFile
	if err = json.Unmarshal(initialKeysContent, &keyJson); err != nil {
		return "", nil
	}

	keysCreated := createdKeysJson{
		Keys: make([]createdKeyJson, 0, len(keyJson.Keys)),
	}
	for _, k := range keyJson.Keys {
		keyCreated, err := impl.GenerateKey(context.Background(), kms.KeySpec{
			Alg:    k.Alg,
			Type:   k.Type,
			KeyOps: k.KeyOps,
			Use:    k.Use,
		})
		if err != nil {
			return "", err
		}
		keysCreated.Keys = append(keysCreated.Keys, createdKeyJson{
			ID:  keyCreated.GetID(),
			Alg: string(keyCreated.GetKeySpec().Alg),
		})
	}

	response, err := json.Marshal(keysCreated)

	if err != nil {
		return "", err
	}

	return string(response), nil
}
