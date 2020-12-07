package filecrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"io"
)

type encryptedData []byte
type decryptedData []byte
type hash string

func createHashSHA256(key string) hash {
	hasher := sha256.New()
	hasher.Write([]byte(key))
	hashS := hasher.Sum(nil)
	return hash(hashS)
}

func encryptSHA256(data []byte, p Passphrase) (encryptedData, error) {
	// convert string to bytes
	key := createHashSHA256(string(p))

	// create a new cipher block from the key
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return nil, err
	}

	// create a new GCM
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// create a nonce
	nonce := make([]byte, aesGCM.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	// encrypt the data using aesGCM.Seal
	cipherData := aesGCM.Seal(nonce, nonce, data, nil)
	return cipherData, nil

}

func decryptSHA256(data []byte, p Passphrase) (decryptedData, error) {
	key := createHashSHA256(string(p))

	// create a new cipher block from the key
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return nil, err
	}

	// create a new GCM
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// get the nonce sizw
	nonceSize := aesGCM.NonceSize()

	// extract the nonce form the encrypted data
	nonce, cipherText := data[:nonceSize], data[nonceSize:]

	// decrypt the data
	plainData, err := aesGCM.Open(nil, nonce, cipherText, nil)
	if err != nil {
		return nil, err
	}
	return plainData, nil
}
