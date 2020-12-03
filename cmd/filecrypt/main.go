package main

import (
	"flag"
	"fmt"
	"github.com/flew-software/filecrypt"
	"os"
	"strings"
)

// file crypt encrypted file
const fileCryptExtension string = ".fcef"

func main() {
	// flag vars
	var (
		fileLocation string
		password     string
		mode         string
		force        bool
	)

	// flags
	flag.StringVar(&fileLocation, "location", "./", "Location of the file")
	flag.StringVar(&password, "password", "default", "Password to use while encrypting/decrypting")
	flag.StringVar(&mode, "mode", "undefined", "FileCrypt mode (encrypt/decrypt)")
	flag.BoolVar(&force, "force", false, "Force write even if a file exists with that name (overwrite)")
	flag.Parse()

	app := filecrypt.App{
		FileCryptExtension: fileCryptExtension,
		Overwrite:          force,
	}

	switch strings.ToLower(mode) {
	case "encrypt", "e":
		newFile, err := app.Encrypt(fileLocation, filecrypt.Passphrase(password))
		if err != nil {
			fmt.Printf("could not encrypt file: %s\n", err)
			os.Exit(1)
		}
		fmt.Printf("file encrypted:\n%s\n", newFile)

	case "decrypt", "d":
		newFile, err := app.Decrypt(fileLocation, filecrypt.Passphrase(password))
		if err != nil {
			fmt.Printf("could not decrypt file: %s\n", err)
			os.Exit(1)
		}
		fmt.Printf("file decrypted:\n%s\n", newFile)
	default:
		fmt.Printf("unhandled mode: %s\n", mode)
		os.Exit(1)
	}
}
