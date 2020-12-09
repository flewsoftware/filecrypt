package filecrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"golang.org/x/crypto/argon2"
	"io"
	"log"
	"strings"
)

type encryptedData []byte
type decryptedData []byte
type hash string

const saltSize = 16
const encryptionVer string = "v0002" + "\n"

var supportedVersions = []string{"v0002"}

func createHashArgon(key string, salt []byte) (hash, error) {
	return hash(argon2.IDKey([]byte(key), salt, 1, 60*1024, 4, 32)), nil
}

func encryptSHA256(data []byte, p Passphrase) (encryptedData, error) {
	salt := make([]byte, saltSize)

	// Generate a Salt
	if _, err := rand.Read(salt); err != nil {
		return encryptedData(""), err
	}

	// convert string to bytes
	key, err := createHashArgon(string(p), salt)
	log.Println(len(key))
	if err != nil {
		return nil, err
	}

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
	cipherData := append([]byte(encryptionVer), salt...)
	cipherData = append(cipherData, aesGCM.Seal(nonce, nonce, data, nil)...)
	return cipherData, nil

}

func decryptSHA256(data []byte, p Passphrase) (decryptedData, error) {
	ver, SaltAndMix := data[:len(encryptionVer)], data[len(encryptionVer):]
	log.Println(string(ver))
	if !checkSupport(string(ver)) {
		return nil, errors.New("version not supported")
	}

	salt, mix := SaltAndMix[:saltSize], SaltAndMix[saltSize:] // salt
	key, err := createHashArgon(string(p), salt)
	if err != nil {
		return nil, err
	}

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

	// get the nonce size
	nonceSize := aesGCM.NonceSize()

	// extract the nonce form the encrypted data
	nonce, cipherText := mix[:nonceSize], mix[nonceSize:]

	// decrypt the data
	plainData, err := aesGCM.Open(nil, nonce, cipherText, nil)
	if err != nil {
		return nil, err
	}
	return plainData, nil
}
func checkSupport(ver string) bool {
	for i := 0; i < len(supportedVersions); i++ {
		if supportedVersions[i] == strings.Replace(ver, "\n", "", -1) {
			return true
		}
	}
	return false
}
