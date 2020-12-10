package filecrypt

import (
	"fmt"
	"io/ioutil"
	"os"
	"strings"
)

// App contains the actual application logic.
type App struct {
	// FileCryptExtension is the file extension of encrypted files.
	FileCryptExtension string
	// Overwrite defines whether or not to overwrite existing files.
	Overwrite bool
}

// Encrypt encrypts the given file and returns the path the an encrypted file.
func (a *App) Encrypt(fileLocation string, password Passphrase) (string, error) {
	if err := password.validate(); err != nil {
		return "", err
	}

	outputFilepath := fmt.Sprintf("%s%s", fileLocation, a.FileCryptExtension)

	if fileExists(outputFilepath) && !a.Overwrite {
		return "", fmt.Errorf("file already exists [%s]. use --force flag to overwrite", outputFilepath)
	}

	fileData, err := ioutil.ReadFile(fileLocation)
	if err != nil {
		return "", fmt.Errorf("could not read file [%s]: %w", fileLocation, err)
	}

	encryptedFileData, err := EncryptSHA256(fileData, password)
	if err != nil {
		return "", fmt.Errorf("could not encrypt data: %w", err)
	}

	// creates a file
	nf, err := os.Create(outputFilepath)
	if err != nil {
		return "", fmt.Errorf("could not create output file [%s]: %w", outputFilepath, err)
	}
	defer nf.Close()

	// writes the encrypted data slice to the file
	_, writeErr := nf.Write(encryptedFileData)
	if writeErr != nil {
		return "", fmt.Errorf("could not write encrypted data to file: %w", err)
	}

	return outputFilepath, nil
}

// Decrypt decrypts the given file and returns the path to an unencrypted file.
func (a *App) Decrypt(fileLocation string, password Passphrase) (string, error) {
	realFile := strings.Replace(fileLocation, a.FileCryptExtension, "", -1)
	if fileLocation == realFile {
		return "", fmt.Errorf("input file does not contain a valid extension: expected %s", a.FileCryptExtension)
	}

	// Checks if file exists
	if fileExists(realFile) && !a.Overwrite {
		return "", fmt.Errorf("file already exists [%s]. use --force flag to overwrite", realFile)
	}

	// reads the file
	b, readErr := ioutil.ReadFile(fileLocation)
	if readErr != nil {
		return "", fmt.Errorf("could not read input file [%s]: %w", fileLocation, readErr)
	}

	// decrypted byte slice
	clearText, err := DecryptSHA256(b, password)
	if err != nil {
		return "", fmt.Errorf("could not decrypt file: %w", err)
	}

	// creates a file
	nf, err := os.Create(realFile)
	if err != nil {
		return "", fmt.Errorf("could not create unencrypted file [%s]: %w", realFile, err)
	}
	defer nf.Close()

	// writes decrypted buffer to the file
	_, writeErr := nf.Write(clearText)
	if writeErr != nil {
		return "", fmt.Errorf("could not write to unencrypted file: %w", err)
	}

	return realFile, nil
}
