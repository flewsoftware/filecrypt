package filecrypt

import "fmt"

// Passphrase is a password.
type Passphrase string

const minPasswordLength = 4

// String returns the Passphrase as a string.
func (p Passphrase) String() string {
	return string(p)
}

func (p *Passphrase) validate() error {
	pString := string(*p)
	if len(p.String()) < minPasswordLength {
		return fmt.Errorf("password must be at least %d characters in length", minPasswordLength-1)
	} else if pString == "default" {
		return fmt.Errorf("non-default password required")
	}
	return nil
}
