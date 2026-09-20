// Copyright 2021 Bret Jordan & Benedikt Thoma, All rights reserved.
// Copyright 2006-2019 WebPKI.org (http://webpki.org).
//
// Use of this source code is governed by an Apache 2.0 license that can be
// found in the LICENSE file in the root of the source tree.

package jcs

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

const (
	pathTestData                 = "./testdata"
	pathInputRelativeToTestData  = "/input"
	pathOutputRelativeToTestData = "/output"
)

func failedBecause(errormsg string) string {
	return fmt.Sprintf("Failed because %s", errormsg)
}

func errorOccurred(activity string, err error) string {
	return failedBecause(fmt.Sprintf("an error occurred while %s: %s\n", activity, err))
}

func doesNotMatchExpected(expectedField, expectedValue, actualField, actualValue string) string {
	return failedBecause(
		fmt.Sprintf(
			"%s [%s] does not match expected %s [%s]\n",
			actualField,
			actualValue,
			expectedField,
			expectedValue,
		),
	)
}

func TestTransform(t *testing.T) {
	testCases := []struct {
		desc     string
		filename string
	}{
		{
			desc:     "Null",
			filename: "null.json",
		},
		{
			desc:     "True",
			filename: "true.json",
		},
		{
			desc:     "False",
			filename: "false.json",
		},
		{
			desc:     "Arrays",
			filename: "arrays.json",
		},
		{
			desc:     "French",
			filename: "french.json",
		},
		{
			desc:     "SimpleString",
			filename: "simpleString.json",
		},
		{
			desc:     "Structures",
			filename: "structures.json",
		},
		{
			desc:     "Unicode",
			filename: "unicode.json",
		},
		{
			desc:     "Values",
			filename: "values.json",
		},
		{
			desc:     "Weird",
			filename: "weird.json",
		},
	}
	for _, tC := range testCases {
		t.Run(tC.desc, func(t *testing.T) {
			tC := tC
			t.Parallel()
			r := require.New(t)

			input, err := os.ReadFile(filepath.Join(pathTestData,
				pathInputRelativeToTestData, tC.filename))
			r.NoError(err, errorOccurred("reading test input json", err))

			output, err := os.ReadFile(filepath.Join(pathTestData,
				pathOutputRelativeToTestData, tC.filename))
			r.NoError(err, errorOccurred("reading expected transformed output sample", err))

			transformed, err := Transform(input)
			r.NoError(err, errorOccurred("transforming test input", err))

			twiceTransformed, err := Transform(input)
			r.NoError(err, errorOccurred("transforming transformed input", err))

			r.True(
				bytes.Equal(transformed, output),
				doesNotMatchExpected(
					"JSON",
					string(output),
					"transformed JSON",
					string(transformed),
				),
			)
			r.True(
				bytes.Equal(twiceTransformed, transformed),
				doesNotMatchExpected(
					"transformed JSON",
					string(transformed),
					"twice transformed JSON",
					string(twiceTransformed),
				),
			)
		})
	}
}

// TestTransformRejectsExcessiveNesting guards against a regression of the
// unbounded recursion denial of service, where a deeply nested JSON payload
// (for example a long run of '[' characters) grows the recursive descent
// parser's call stack until the Go runtime aborts the whole process with a
// fatal, unrecoverable stack overflow. Transform must instead return an
// ordinary error once the nesting depth exceeds maxNestingDepth.
func TestTransformRejectsExcessiveNesting(t *testing.T) {
	r := require.New(t)

	testCases := []struct {
		desc string
		open byte
		shut byte
	}{
		{desc: "Arrays", open: '[', shut: ']'},
		{desc: "Objects", open: '{', shut: '}'},
	}

	for _, tC := range testCases {
		tC := tC
		t.Run(tC.desc, func(t *testing.T) {
			t.Parallel()
			r := require.New(t)

			depth := maxNestingDepth + 1
			payload := make([]byte, 0, depth*2)
			for i := 0; i < depth; i++ {
				payload = append(payload, tC.open)
			}
			for i := 0; i < depth; i++ {
				payload = append(payload, tC.shut)
			}

			_, err := Transform(payload)
			r.Error(err, "Transform should reject a payload nested deeper than maxNestingDepth")
		})
	}

	// A payload nested just within the bound must still transform normally,
	// confirming that legitimate, deeply structured documents are unaffected.
	within := maxNestingDepth - 1
	payload := make([]byte, 0, within*2)
	for i := 0; i < within; i++ {
		payload = append(payload, '[')
	}
	for i := 0; i < within; i++ {
		payload = append(payload, ']')
	}
	_, err := Transform(payload)
	r.NoError(err, errorOccurred("transforming an array nested just within maxNestingDepth", err))
}

// TestTransformRejectsMalformedObjectKey guards against a regression where
// parseObject swallowed an error from parsing a property name (truncated
// input, a raw control character, or an invalid escape inside the key) by
// breaking out of its parsing loop instead of propagating the error. That bug
// let Transform silently serialize whatever name/value pairs it had already
// collected and return them with a nil error, so a truncated or corrupted
// object such as {"amount":100,"recipient was canonicalized to {"amount":100}
// with no indication that trailing members were dropped.
func TestTransformRejectsMalformedObjectKey(t *testing.T) {
	testCases := []struct {
		desc  string
		input []byte
	}{
		{
			desc:  "TruncatedMidKey",
			input: []byte(`{"amount":100,"recipient`),
		},
		{
			desc:  "TruncatedRightAfterOpeningKeyQuote",
			input: []byte(`{"amount":100,"`),
		},
		{
			desc:  "ControlCharacterInKeyThenEOF",
			input: append([]byte(`{"amount":100,"x`), 0x01),
		},
		{
			desc:  "BadEscapeInKeyThenEOF",
			input: []byte(`{"amount":100,"x\q`),
		},
		{
			desc:  "MinimalTruncatedKey",
			input: []byte(`{"`),
		},
		{
			desc:  "ControlCharacterInKeyThenTrailingWhitespace",
			input: append(append([]byte(`{"amount":100,"x`), 0x0A), []byte("   ")...),
		},
	}

	for _, tC := range testCases {
		tC := tC
		t.Run(tC.desc, func(t *testing.T) {
			t.Parallel()
			r := require.New(t)

			_, err := Transform(tC.input)
			r.Error(err, "Transform should reject an object with a malformed or truncated key instead of silently dropping trailing members")
		})
	}
}

// TestTransformRejectsInvalidSurrogatePairs guards against a regression
// where a \u escape naming a lone or mis-ordered UTF-16 surrogate was passed
// straight to utf16.DecodeRune without validating that the first code unit
// is a high surrogate and the second is a low surrogate. DecodeRune returns
// the Unicode replacement character (U+FFFD) for any invalid pairing rather
// than signaling an error, so distinct ill-formed inputs such as
// "\uD800\uD800", "\uDC00\uDC00", and "\uDC00\uD800" all canonicalized to
// the identical byte sequence with a nil error, violating both RFC 8785's
// requirement that invalid surrogates cause an error and the injectivity
// that a canonicalizer must preserve.
func TestTransformRejectsInvalidSurrogatePairs(t *testing.T) {
	testCases := []struct {
		desc  string
		input string
	}{
		{desc: "HighThenHigh", input: `["\uD800\uD800"]`},
		{desc: "LowThenLow", input: `["\uDC00\uDC00"]`},
		{desc: "LowThenHigh", input: `["\uDC00\uD800"]`},
		{desc: "ArbitraryLowThenLow", input: `["\uDEAD\uDEAD"]`},
	}

	for _, tC := range testCases {
		tC := tC
		t.Run(tC.desc, func(t *testing.T) {
			t.Parallel()
			r := require.New(t)

			_, err := Transform([]byte(tC.input))
			r.Error(err, "Transform should reject an invalid or mis-ordered surrogate pair instead of silently emitting U+FFFD")
		})
	}

	// A valid, correctly ordered surrogate pair must still decode normally.
	r := require.New(t)
	transformed, err := Transform([]byte(`["😀"]`))
	r.NoError(err, errorOccurred("transforming a valid high+low surrogate pair", err))
	r.Equal("[\"\U0001F600\"]", string(transformed), "a valid surrogate pair should decode to the corresponding rune")
}
