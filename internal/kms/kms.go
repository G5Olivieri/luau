package kms

import (
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
)

var (
	ErrInvalidSignature = errors.New("invalid signature")
	ErrInvalidMAC       = errors.New("invalid MAC")
)

// KMS é a interface estendida que agora inclui métodos para operações criptográficas.
type KMS interface {
	CreateKey(ctx context.Context, metadata map[string]string) (key *Key, err error)
	GetKey(ctx context.Context, keyID string) (key *Key, err error)
	RotateKey(ctx context.Context, keyID string) error
	DeleteKey(ctx context.Context, keyID string) error
	Sign(ctx context.Context, keyID string, data []byte) (signature []byte, err error)
	Verify(ctx context.Context, keyID string, data, signature []byte) (valid bool, err error)
	Encrypt(ctx context.Context, keyID string, plaintext []byte) (ciphertext []byte, err error)
	Decrypt(ctx context.Context, keyID string, ciphertext []byte) (plaintext []byte, err error)
	GenerateMAC(ctx context.Context, keyID string, data []byte) (mac []byte, err error)
	VerifyMAC(ctx context.Context, keyID string, data, mac []byte) (valid bool, err error)
}

// InMemoryKMS é a implementação do KMS que armazena chaves na memória.
type InMemoryKMS struct {
	keys map[string]*Key
}

type KeySpec struct {
	Name string
}

// Key representa uma chave criptográfica com suporte a diferentes tipos (e.g., RSA, AES).
type Key struct {
	ID       string
	KeySpec  KeySpec
	Value    []byte // A chave privada ou simétrica em formato bruto.
	Metadata map[string]string
}

func NewInMemoryKMS() *InMemoryKMS {
	return &InMemoryKMS{
		keys: make(map[string]*Key),
	}
}

// Implementações dos métodos CreateKey, GetKey, RotateKey, DeleteKey vão aqui...
func (kms *InMemoryKMS) CreateKey(ctx context.Context, id string, keySpec KeySpec, metadata map[string]string) (key *Key, err error) {
	if keySpec.Name == "HMAC" {
		randomValue := make([]byte, 32)
		_, err := rand.Read(randomValue)
		if err != nil {
			return nil, err
		}

		key = &Key{
			ID:       id,
			KeySpec:  keySpec,
			Metadata: metadata,
			Value:    randomValue,
		}

		kms.keys[id] = key
		return key, nil
	}
	if keySpec.Name == "AES" {
	}
	if keySpec.Name == "RSA" {
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, err
		}

		key = &Key{
			ID:       id,
			KeySpec:  keySpec,
			Metadata: metadata,
			Value:    []byte(""),
		}
	}
	// TODO: RSAPSS
	// TODO: ECDSA
	// TODO: ED25519
}

func (kms *InMemoryKMS) GetKey(ctx context.Context, keyID string) (key *Key, err error)
func (kms *InMemoryKMS) RotateKey(ctx context.Context, keyID string) error
func (kms *InMemoryKMS) DeleteKey(ctx context.Context, keyID string) error

// Sign cria uma assinatura digital para os dados fornecidos usando a chave privada RSA.
func (kms *InMemoryKMS) Sign(ctx context.Context, keyID string, data []byte) (signature []byte, err error) {
	key, err := kms.GetKey(ctx, keyID)
	if err != nil {
		return nil, err
	}

	if key.keySpec.Name != "RSA" {
		return nil, errors.New("key type must be RSA for signing")
	}

	privKey, err := rsa.ParsePrivateKey(key.Value)
	if err != nil {
		return nil, err
	}

	h := sha256.New()
	h.Write(data)
	digest := h.Sum(nil)

	signature, err = rsa.SignPKCS1v15(rand.Reader, privKey, crypto.SHA256, digest)
	if err != nil {
		return nil, err
	}

	return signature, nil
}

// Verify verifica a assinatura digital dos dados fornecidos usando a chave pública RSA.
func (kms *InMemoryKMS) Verify(ctx context.Context, keyID string, data, signature []byte) (valid bool, err error) {
	key, err := kms.GetKey(ctx, keyID)
	if err != nil {
		return false, err
	}

	if key.Type != "RSA" {
		return false, errors.New("key type must be RSA for verification")
	}

	pubKey, err := rsa.ParseRSAPublicKeyFromPEM(key.Value)
	if err != nil {
		return false, err
	}

	h := sha256.New()
	h.Write(data)
	digest := h.Sum(nil)

	if err := rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, digest, signature); err != nil {
		return false, ErrInvalidSignature
	}

	return true, nil
}

// Encrypt criptografa os dados fornecidos usando a chave AES.
func (kms *InMemoryKMS) Encrypt(ctx context.Context, keyID string, plaintext []byte) (ciphertext []byte, err error) {
	key, err := kms.GetKey(ctx, keyID)
	if err != nil {
		return nil, err
	}

	if key.Type != "AES" {
		return nil, errors.New("key type must be AES for encryption")
	}

	block, err := aes.NewCipher(key.Value)
	if err != nil {
		return nil, err
	}

	ciphertext = make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)

	return ciphertext, nil
}

// Decrypt descriptografa os dados fornecidos usando a chave AES.
func (kms *InMemoryKMS) Decrypt(ctx context.Context, keyID string, ciphertext []byte) (plaintext []byte, err error) {
	key, err := kms.GetKey(ctx, keyID)
	if err != nil {
		return nil, err
	}

	if key.Type != "AES" {
		return nil, errors.New("key type must be AES for decryption")
	}

	block, err := aes.NewCipher(key.Value)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < aes.BlockSize {
		return nil, errors.New("ciphertext too short")
	}

	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(ciphertext, ciphertext)

	return ciphertext, nil
}

// GenerateMAC gera um MAC para os dados fornecidos usando a chave HMAC.
func (kms *InMemoryKMS) GenerateMAC(ctx context.Context, keyID string, data []byte) (mac []byte, err error) {
	key, err := kms.GetKey(ctx, keyID)
	if err != nil {
		return nil, err
	}

	if key.Type != "HMAC" {
		return nil, errors.New("key type must be HMAC for MAC generation")
	}

	mac = hmac.New(sha256.New, key.Value)
	mac.Write(data)
	return mac.Sum(nil), nil
}

// VerifyMAC verifica um MAC para os dados fornecidos usando a chave HMAC.
func (kms *InMemoryKMS) VerifyMAC(ctx context.Context, keyID string, data, mac []byte) (valid bool, err error) {
	expectedMAC, err := kms.GenerateMAC(ctx, keyID, data)
	if err != nil {
		return false, err
	}

	if !hmac.Equal(expectedMAC, mac) {
		return false, ErrInvalidMAC
	}

	return true, nil
}
