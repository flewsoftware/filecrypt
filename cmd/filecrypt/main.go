package main

import (
	"bufio"
	"flag"
	"fmt"
	"github.com/flew-software/filecrypt/v2"
	"os"
	"strings"
)

// file crypt encrypted file
const fileCryptExtension string = ".fcef"

func main() {
	reader := bufio.NewReader(os.Stdin)
	// flag vars
	var (
		fileLocation string
		password     string
		mode         string
		force        bool
	)

	// flags
	flag.StringVar(&fileLocation, "location", "./", "Location of the file")
	flag.StringVar(&mode, "mode", "undefined", "FileCrypt mode (encrypt/decrypt)")
	flag.BoolVar(&force, "force", false, "Force write even if a file exists with that name (overwrite)")
	flag.Parse()

	app := v2.App{
		FileCryptExtension: fileCryptExtension,
		Overwrite:          force,
	}
	// asks for password
	print("Enter a password> ")
	password, _ = reader.ReadString('\n')
	password = strings.Replace(password, "\n", "", -1)

	switch strings.ToLower(mode) {
	case "encrypt", "e":
		newFile, err := app.Encrypt(fileLocation, v2.Passphrase(password))
		if err != nil {
			fmt.Printf("could not encrypt file: %s\n", err)
			os.Exit(1)
		}
		fmt.Printf("file encrypted:\n%s\n", newFile)

	case "decrypt", "d":
		newFile, err := app.Decrypt(fileLocation, v2.Passphrase(password))
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
