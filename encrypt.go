package main

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
)

const byte16, byte24, byte32 int = 16, 24, 32

func GenerateAESKey(keySizeInBytes int) (key []byte, err error) {
	isValid := (keySizeInBytes == byte16 || keySizeInBytes == byte24 || keySizeInBytes == byte32)
	if !isValid {
		return nil, fmt.Errorf("invalid keysize %d", keySizeInBytes)
	}
	key = make([]byte, keySizeInBytes)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generate single key: %w", err)
	}
	return key, nil
}

func WriteAESKeyToPemFile(key []byte, filename string) (err error) {
	pemBlock := &pem.Block{
		Type:  "AES KEY",
		Bytes: key,
	}

	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("error creating pem file: %w", err)
	}

	defer file.Close()

	err = pem.Encode(file, pemBlock)
	if err != nil {
		return fmt.Errorf("error encoding pem file: %w", err)
	}
	return nil
}

func CreateAESKeytoPemFile(keySizeInBytes int, filename string) (err error) {
	key, err := GenerateAESKey(keySizeInBytes)
	if err != nil {
		return fmt.Errorf("error generating aes key: %w", err)
	}
	err = WriteAESKeyToPemFile(key, filename)
	if err != nil {
		return fmt.Errorf("error writing aes key to pem file: %w", err)
	}
	return nil
}

func AESEncryptWithGCM(plaintext []byte, aes cipher.Block) (ciphertext []byte, err error) {
	gcm, err := cipher.NewGCM(aes)
	if err != nil {
		return nil, fmt.Errorf("cannot make new gcm: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("error making nonce: %w", err)
	}

	ciphertext = gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

func AESDecryptWithGCM(ciphertext []byte, aes cipher.Block) (plaintext []byte, err error) {
	gcm, err := cipher.NewGCM(aes)
	if err != nil {
		return nil, fmt.Errorf("cannot create new gcm: %w", err)
	}

	nonceSize := gcm.NonceSize()
	stringCipherText := ciphertext
	nonce, stringCipherText := stringCipherText[:nonceSize], stringCipherText[nonceSize:]

	decrypted, err := gcm.Open(nil, nonce, stringCipherText, nil)
	if err != nil {
		return nil, fmt.Errorf("error opening and authenticating ciphertext: %w", err)
	}

	return decrypted, nil
}

func ReadAESKeyFromPemFile(filename string) (key []byte, err error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("cannot read file: %w", err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("cannot decode pem data")
	}

	if block.Type != "AES KEY" {
		return nil, fmt.Errorf("expected block type 'AES KEY' got %s", block.Type)
	}
	return block.Bytes, nil
}
