package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"io"
	"io/ioutil"
	"log"
	"os"
	"strings"
	"sync"
)

// file crypt encrypted file
const fileCryptExtension string = ".fcef"

type passphrase string
type encryptedData []byte
type decryptedData []byte
type hash string

func (p *passphrase) validate() bool {
	pString := string(*p)
	if len(pString) < 4 {
		return false
	} else if pString == "default" {
		return false
	}
	return true
}

func createHash(key string) hash {
	hasher := md5.New()
	hasher.Write([]byte(key))
	return hash(hex.EncodeToString(hasher.Sum(nil)))
}
func encrypt(data []byte, p passphrase, channel chan encryptedData, wg *sync.WaitGroup) {
	defer wg.Done()
	block, _ := aes.NewCipher([]byte(createHash(string(p))))
	gcm, _ := cipher.NewGCM(block)
	nonce := make([]byte, gcm.NonceSize())
	_, _ = io.ReadFull(rand.Reader, nonce)
	cipherText := gcm.Seal(nonce, nonce, data, nil)
	channel <- cipherText
}
func decrypt(data []byte, p passphrase) decryptedData {
	key := []byte(createHash(string(p)))
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	nonceSize := gcm.NonceSize()
	nonce, cipherText := data[:nonceSize], data[nonceSize:]
	plainText, _ := gcm.Open(nil, nonce, cipherText, nil)
	return plainText
}

func main() {
	// flag vars
        var (
	    fileLocation string
	    password passphrase
	    encryptB = false
	    decryptB = false
	    mode string
	    force bool
        )

	// flags
	flag.StringVar(&fileLocation, "location", "./", "Location of the file")
	flag.StringVar((*string)(&password), "password", "default", "Password to use while encrypting/decrypting")
	flag.StringVar(&mode, "mode", "undefined", "FileCrypt mode (encrypt/decrypt)")
	flag.BoolVar(&force, "force", false, "Force write even if a file exists with that name (overwrite)")
	flag.Parse()

	// checks if required flags are present
	if strings.ToLower(mode) == "encrypt" || strings.ToLower(mode) == "e" {
		encryptB = true
	} else if strings.ToLower(mode) == "decrypt" || strings.ToLower(mode) == "d" {
		decryptB = true
	} else {
		log.Fatalln("No encrypt or decrypt flag provided")
	}

	writeFileMain := func() {

		// Checks if file exists
		val := exists(fileLocation + fileCryptExtension)
		if val {
			if force {
				println("Overwriting file because of the usage of the \"--force\" flag")
			} else {
				log.Fatalln("File already exists Use the flag \"--force\" to overwrite the file")
			}
		}

		if encryptB {

			var wg sync.WaitGroup

			// validates password
			if password.validate() == false {
				log.Fatalln("password too small must have at least 2 letters or password is default")
			}

			log.Println("Reading " + fileLocation)
			// reads the file
			readChan := make(chan []byte)
			wg.Add(1)
			go readFile(fileLocation, readChan, &wg)
			b := <-readChan
			wg.Wait()
			log.Println("Read " + fileLocation)

			log.Println("Encrypting file")
			// encrypted byte slice
			byteSliceChan := make(chan encryptedData)
			wg.Add(1)
			go encrypt(b, password, byteSliceChan, &wg)
			cipherText := <-byteSliceChan
			wg.Wait()
			log.Println("Encrypted file " + fileLocation)

			log.Println("Creating " + fileCryptExtension + " file")
			// creates a file
			nf, err := os.Create(fileLocation + fileCryptExtension)
			if err != nil {
				log.Fatalln(err)
			}
			defer nf.Close()
			log.Println("Created " + fileLocation)

			log.Println("Writing encrypted data to " + fileLocation + fileCryptExtension)
			// writes the encrypted data slice to the file
			_, writeErr := nf.Write(cipherText)
			if writeErr != nil {
				log.Fatalln(writeErr)
			}
			log.Println("Success!")

		} else if decryptB {

			realFile := strings.Replace(fileLocation, fileCryptExtension, "", -1)
			if fileLocation == realFile {
				log.Fatalln("Not a " + fileCryptExtension + " file")
			}

			log.Println("Checking if " + fileLocation + " exists")
			// Checks if file exists
			val := exists(realFile)
			if val {
				if force {
					println("Overwriting file because of the usage of the \"--force\" flag")
				} else {
					log.Fatalln("File already exists Use the flag \"--force\" to overwrite the file")
				}
			} else {
				log.Println("File exists")
			}

			log.Println("Reading " + fileLocation)
			// reads the file
			b, readErr := ioutil.ReadFile(fileLocation)
			if readErr != nil {
				log.Fatalln(readErr)
			}
			log.Println("Read " + fileLocation)

			log.Println("Decrypting file")
			// decrypted byte slice
			clearText := decrypt(b, password)
			log.Println("Decrypted file " + fileLocation)

			log.Println("Creating decrypted file " + realFile)
			// creates a file
			nf, err := os.Create(strings.Replace(fileLocation, fileCryptExtension, "", -1))
			if err != nil {
				log.Fatalln(err)
			}
			defer nf.Close()
			log.Println("Created " + realFile)

			log.Println("Writing decrypted data to" + realFile)
			// writes decrypted buffer to the file
			_, writeErr := nf.Write(clearText)
			if writeErr != nil {
				log.Fatalln(writeErr)
			}
			log.Println("Success!")

		}
	}
	writeFileMain()

}

func readFile(fileLocation string, readChan chan []byte, wg *sync.WaitGroup) {
	b, readErr := ioutil.ReadFile(fileLocation)
	if readErr != nil {
		log.Fatalln(readErr)
	}
	defer wg.Done()
	readChan <- b
}

/*Checks if a file exists in the given location
  returns true if the file already exists*/
func exists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}
