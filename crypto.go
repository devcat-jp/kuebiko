package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
)

// generateKey creates a new random 32-byte AES key.
func generateKey() (string, error) {
	b := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

// decodeKey returns the raw bytes for an AES key.
func decodeKey(keyB64 string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(keyB64)
}

// encrypt encrypts plaintext with AES-GCM using the provided base64 key.
func encrypt(plaintext, keyB64 string) (string, error) {
	key, err := decodeKey(keyB64)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// decryptBytes decrypts a base64 ciphertext into raw bytes.
func decryptBytes(ciphertextB64, keyB64 string) ([]byte, error) {
	pt, err := decrypt(ciphertextB64, keyB64)
	if err != nil {
		return nil, err
	}
	return []byte(pt), nil
}

// encryptBytes encrypts raw bytes with AES-GCM and returns base64 ciphertext.
func encryptBytes(plaintext []byte, keyB64 string) (string, error) {
	return encrypt(string(plaintext), keyB64)
}

// decrypt decrypts a base64 ciphertext with AES-GCM using the provided base64 key.
func decrypt(ciphertextB64, keyB64 string) (string, error) {
	key, err := decodeKey(keyB64)
	if err != nil {
		return "", err
	}
	ciphertext, err := base64.StdEncoding.DecodeString(ciphertextB64)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(ciphertext) < gcm.NonceSize() {
		return "", fmt.Errorf("ciphertext too short")
	}
	nonce, ct := ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():]
	pt, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return "", err
	}
	return string(pt), nil
}
