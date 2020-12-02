package filecrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
)

type encryptedData []byte
type decryptedData []byte
type hash string

func createHash(key string) hash {
	hasher := md5.New()
	hasher.Write([]byte(key))
	return hash(hex.EncodeToString(hasher.Sum(nil)))
}

func encrypt(data []byte, p Passphrase) (encryptedData, error) {
	block, _ := aes.NewCipher([]byte(createHash(string(p))))
	gcm, _ := cipher.NewGCM(block)
	nonce := make([]byte, gcm.NonceSize())
	_, err := io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return nil, fmt.Errorf("could not get nonce: %w", err)
	}
	cipherText := gcm.Seal(nonce, nonce, data, nil)
	return cipherText, nil
}

func decrypt(data []byte, p Passphrase) (decryptedData, error) {
	key := []byte(createHash(string(p)))
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	nonceSize := gcm.NonceSize()
	nonce, cipherText := data[:nonceSize], data[nonceSize:]
	plainText, err := gcm.Open(nil, nonce, cipherText, nil)
	return plainText, err
}
