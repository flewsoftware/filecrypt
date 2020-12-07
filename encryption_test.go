package filecrypt

import (
	"fmt"
	"testing"
)

func TestEncryptDecrypt(t *testing.T) {
	var tests = []struct {
		input      string
		passphrase Passphrase
	}{
		{"log", Passphrase("popcorn")},
		{"log", Passphrase("pa$$word")},
		{"log", Passphrase("pdsasdas")},
		{"log", Passphrase("[asdsdasdmasn]")},
		{"log", Passphrase("popwas")},
		{"log", Passphrase("oi0isas")},
		{"log", Passphrase("0=2oasdaj")},
		{"test", Passphrase("testPass")},
		{"test", Passphrase("asdasdasd")},
		{"test", Passphrase("testP[ss")},
		{"test", Passphrase("195s2f5")},
		{"test", Passphrase("%%%%%%%s")},
		{"test", Passphrase("#491k2@")},
		{"test", Passphrase("[]'fd;fo;hkaf")},
	}
	for k, test := range tests {
		testCase := test
		t.Run(fmt.Sprint(k), func(t *testing.T) {
			encryptedResults, err := encryptSHA256([]byte(testCase.input), testCase.passphrase)
			if err != nil {
				t.Errorf("unexpected error: %s", err)
				return
			}

			decryptedResults, err := decryptSHA256(encryptedResults, testCase.passphrase)
			if err != nil {
				t.Errorf("unexpected error: %s", err)
				return
			}

			if exp, got := string(decryptedResults), testCase.input; exp != got {
				t.Errorf("expected result %s, got %s", exp, got)
			}
		})
	}
}
