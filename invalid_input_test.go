package jcs

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// Inputs that are not valid JSON, or not valid UTF-8, must be refused rather than
// canonicalized. Found by running the same inputs through four RFC 8785 libraries.
func TestTransformRefusesInvalidInput(t *testing.T) {
	cases := []struct {
		name  string
		input []byte
	}{
		{"missing comma between array elements", []byte("[1 2]")},
		{"number with a bare decimal point", []byte("[1.]")},
		{"number with a leading plus", []byte("[+1]")},
		{"invalid UTF-8 byte in a string", []byte("[\"\xff\"]")},
		{"overlong encoding in a string", []byte("[\"\xed\xa0\x80\"]")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, err := Transform(tc.input)
			require.Error(t, err, "got %q", out)
		})
	}
}
