package filecrypt

import (
	"fmt"
	"testing"
)

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
		{Passphrase("de"), false},
		{Passphrase("\n"), false},
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
