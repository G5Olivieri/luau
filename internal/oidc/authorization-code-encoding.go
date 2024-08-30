package oidc

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"time"
)

type AuthorizationCodeEncoding interface {
	Encode(authorizationCode AuthorizationCode) (string, error)
	Decode(code string) (AuthorizationCode, error)
}

type AESAuthorizationCodeEncoding struct {
	secret []byte
}

func NewAESAuthorizationCodeEncoding(secret []byte) AESAuthorizationCodeEncoding {
	return AESAuthorizationCodeEncoding{
		secret: secret,
	}
}

func (e AESAuthorizationCodeEncoding) Encode(authorizationCode AuthorizationCode) (string, error) {
	jsonData, err := json.Marshal(authorizationCode)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(e.secret)
	if err != nil {
		return "", err
	}

	ciphertext := make([]byte, aes.BlockSize+len(jsonData))
	iv := ciphertext[:aes.BlockSize]

	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], jsonData)

	return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(ciphertext), nil
}

func (e AESAuthorizationCodeEncoding) Decode(code string) (AuthorizationCode, error) {
	cipherText, err := base64.URLEncoding.WithPadding(base64.NoPadding).DecodeString(code)
	if err != nil {
		return AuthorizationCode{}, err
	}
	block, err := aes.NewCipher(e.secret)
	if err != nil {
		return AuthorizationCode{}, err
	}
	iv := cipherText[:aes.BlockSize]
	cipherText = cipherText[aes.BlockSize:]
	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(cipherText, cipherText)

	var data AuthorizationCode
	if err := json.Unmarshal(cipherText, &data); err != nil {
		return AuthorizationCode{}, err
	}
	if time.Now().Unix() > data.Exp {
		return AuthorizationCode{}, fmt.Errorf("authorization code expired")
	}
	return data, nil

}
