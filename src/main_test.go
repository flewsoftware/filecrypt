package main

import (
	"sync"
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
		passphrase passphrase
	}{
		{"log", passphrase("popcorn")},
		{"log", passphrase("pa$$word")},
		{"log", passphrase("pdsasdas")},
		{"log", passphrase("[asdsdasdmasn]")},
		{"log", passphrase("popwas")},
		{"log", passphrase("oi0isas")},
		{"log", passphrase("0=2oasdaj")},
		{"test", passphrase("testPass")},
		{"test", passphrase("asdasdasd")},
		{"test", passphrase("testP[ss")},
		{"test", passphrase("195s2f5")},
		{"test", passphrase("%%%%%%%s")},
		{"test", passphrase("#491k2@")},
		{"test", passphrase("[]'fd;fo;hkaf")},
	}
	for _, test := range tests {
		var wg sync.WaitGroup
		var encryptedDataChan = make(chan encryptedData)
		wg.Add(1)
		go encrypt([]byte(test.input), test.passphrase, encryptedDataChan, &wg)
		encryptedResults := <-encryptedDataChan
		wg.Wait()

		if decryptedDataRes := string(decrypt(encryptedResults, test.passphrase)); decryptedDataRes != test.input {
			t.Error("Test failed: input:{} expectedOutput:{} output:{}", test.input, test.input, string(decryptedDataRes))
		}

	}
}

func TestPassphraseValidate(t *testing.T) {
	var tests = []struct {
		passphrase passphrase
		valid      bool
	}{
		// valid tests
		{passphrase("popcorn"), true},
		{passphrase("pa$$word"), true},
		{passphrase("pdsasdas"), true},
		{passphrase("[asdsdasdmasn]"), true},
		{passphrase("popwas"), true},
		{passphrase("oi0isas"), true},
		{passphrase("0=2oasdaj"), true},
		{passphrase("testPass"), true},
		{passphrase("asdasdasd"), true},
		{passphrase("testP[ss"), true},
		{passphrase("195s2f5"), true},
		{passphrase("%%%%%%%s"), true},
		{passphrase("#491k2@"), true},

		// invalid tests

		{passphrase("#49"), false},
		{passphrase("#f9"), false},
		{passphrase("as9"), false},
		{passphrase("bn9"), false},
		{passphrase("pop"), false},
		{passphrase("lol"), false},
		{passphrase("123"), false},
	}
	for _, test := range tests {
		pass := test.passphrase
		valid := pass.validate()
		if valid != test.valid {
			t.Error("Test failed: passphrase:{} expectedOutput:{} output:{}", test.passphrase, test.valid, valid)
		}
	}
}
