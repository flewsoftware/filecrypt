package filecrypt

import (
	"fmt"
	"testing"
)

func TestCreateHash(t *testing.T) {
	var tests = []struct {
		input          string
		expectedOutput string
	}{
		{"test", "098f6bcd4621d373cade4e832627b4f6"},
		{"log", "dc1d71bbb5c4d2a5e936db79ef10c19f"},
		{"log", "dc1d71bbb5c4d2a5e936db79ef10c19f"},
	}
	for _, test := range tests {
		if output := createHash(test.input); string(output) != test.expectedOutput {
			t.Error("Test failed: input:{} expectedOutput:{} output:{}", test.input, test.expectedOutput, output)
		}
	}
}

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
			encryptedResults, err := encrypt([]byte(testCase.input), testCase.passphrase)
			if err != nil {
				t.Errorf("unexpected error: %s", err)
				return
			}

			decryptedResults, err := decrypt(encryptedResults, testCase.passphrase)
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

func TestPassphraseValidate(t *testing.T) {
	var tests = []struct {
		passphrase Passphrase
		valid      bool
	}{
		// valid tests
		{Passphrase("popcorn"), true},
		{Passphrase("pa$$word"), true},
		{Passphrase("pdsasdas"), true},
		{Passphrase("[asdsdasdmasn]"), true},
		{Passphrase("popwas"), true},
		{Passphrase("oi0isas"), true},
		{Passphrase("0=2oasdaj"), true},
		{Passphrase("testPass"), true},
		{Passphrase("asdasdasd"), true},
		{Passphrase("testP[ss"), true},
		{Passphrase("195s2f5"), true},
		{Passphrase("%%%%%%%s"), true},
		{Passphrase("#491k2@"), true},

		// invalid tests
		{Passphrase("#49"), false},
		{Passphrase("#f9"), false},
		{Passphrase("as9"), false},
		{Passphrase("bn9"), false},
		{Passphrase("pop"), false},
		{Passphrase("lol"), false},
		{Passphrase("123"), false},
		{Passphrase("default"), false},
	}
	for k, test := range tests {
		testCase := test
		t.Run(fmt.Sprint(k), func(t *testing.T) {
			if exp, got := testCase.valid, testCase.passphrase.validate() == nil; exp != got {
				t.Errorf("expected result %v, got %v", exp, got)
			}
		})
	}
}
