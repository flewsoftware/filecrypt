package filecrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"golang.org/x/crypto/argon2"
	"io"
	"strings"
)

type EncryptedData []byte
type DecryptedData []byte
type Hash string

// default size of a salt(bytes)
const saltSize = 16

// current encryption version(fcef format)
const encryptionVer string = "v0002" + "\n"

// contains all supported fcef format versions
var supportedVersions = []string{"v0002"}

// creates a argon2 Hash from the key
func CreateHashArgon(key string, salt []byte) (Hash, error) {
	return Hash(argon2.IDKey([]byte(key), salt, 1, 60*1024, 4, 32)), nil
}

// encrypts byte slice using the passphrase
func EncryptSHA256(data []byte, p Passphrase) (EncryptedData, error) {
	salt := make([]byte, saltSize)

	// Generate a Salt
	if _, err := rand.Read(salt); err != nil {
		return EncryptedData(""), err
	}

	// convert string to bytes
	key, err := CreateHashArgon(string(p), salt)
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

	// create a nonce (12 bytes)
	nonce := make([]byte, aesGCM.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	// encrypt the data using aesGCM.Seal
	cipherData := append([]byte(encryptionVer), salt...)
	cipherData = append(cipherData, aesGCM.Seal(nonce, nonce, data, nil)...)
	return cipherData, nil

}

// decrypts byte slice using the passphrase
func DecryptSHA256(data []byte, p Passphrase) (DecryptedData, error) {
	// extracts the version number of fcef format from byte slice
	ver, SaltAndMix := data[:len(encryptionVer)], data[len(encryptionVer):]
	if !CheckSupport(string(ver)) {
		return nil, errors.New("version not supported")
	}

	// gets the salt form the byte slice
	salt, mix := SaltAndMix[:saltSize], SaltAndMix[saltSize:]
	key, err := CreateHashArgon(string(p), salt)
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

	// extract the nonce from the encrypted data
	nonce, cipherText := mix[:nonceSize], mix[nonceSize:]

	// decrypt the data
	plainData, err := aesGCM.Open(nil, nonce, cipherText, nil)
	if err != nil {
		return nil, err
	}
	return plainData, nil
}

// checks if current version of FileCrypt supports the fcef format
func CheckSupport(ver string) bool {
	for i := 0; i < len(supportedVersions); i++ {
		if supportedVersions[i] == strings.Replace(ver, "\n", "", -1) {
			return true
		}
	}
	return false
}
