package jcs

import (
	"encoding/json"
	"testing"
	"unicode/utf8"
)

// FuzzTransform asserts the security relevant invariants of the canonicalizer:
// it must never panic, its output must always be valid UTF-8 and valid JSON,
// canonicalization must be idempotent, and it must never accept input that a
// strict RFC 8259 parser rejects.
func FuzzTransform(f *testing.F) {
	seeds := []string{
		`{}`, `[]`, `null`, `true`, `false`, `0`, `-1.5e-7`,
		`{"a":1,"b":[1,2,3]}`,
		`["😀"]`,
		`{"\u0000":"\u001f"}`,
		`[1e21,1e-6,5e-324,1.7976931348623157e308]`,
		`{"b":{"a":[{},[]]}}`,
		"[\"caf\xc3\xa9\"]",
		`  {"a" : 1}  `,
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		out, err := Transform(data)
		if err != nil {
			return
		}

		if !utf8.Valid(out) {
			t.Fatalf("canonical output is not valid UTF-8: input=%q output=%q", data, out)
		}

		var sink interface{}
		if jerr := json.Unmarshal(out, &sink); jerr != nil {
			t.Fatalf("canonical output is not valid JSON: input=%q output=%q err=%v", data, out, jerr)
		}

		// Any input jcs accepts must also be accepted by a strict parser.
		// Duplicate object keys are the one deliberate exception: RFC 8785
		// requires an error where encoding/json takes the last value, and
		// jcs rejects those before reaching this point.
		if jerr := json.Unmarshal(data, &sink); jerr != nil {
			t.Fatalf("parser differential: jcs accepted input that encoding/json rejects: input=%q output=%q jsonErr=%v", data, out, jerr)
		}

		again, err2 := Transform(out)
		if err2 != nil {
			t.Fatalf("canonicalization not idempotent, second pass failed: input=%q output=%q err=%v", data, out, err2)
		}
		if string(again) != string(out) {
			t.Fatalf("canonicalization not idempotent: input=%q first=%q second=%q", data, out, again)
		}
	})
}
