// Copyright 2021-2026 Bret Jordan & Benedikt Thoma, All rights reserved.
// Copyright 2006-2019 WebPKI.org (http://webpki.org).
//
// Use of this source code is governed by an Apache 2.0 license that can be
// found in the LICENSE file in the root of the source tree.

package jcs

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

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
		// The two halves of a valid pair (😀, the grinning-face
		// emoji), given in reversed order. Before the high/low range check
		// was added, this collided with the array holding a literal U+FFFD
		// character, since both canonicalized to the same replacement-
		// character bytes.
		{desc: "ReversedValidPairHalves", input: `["\uDE00\uD83D"]`},
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

// TestTransformRejectsMalformedNumbersAndLiterals guards against a
// regression where parseSimpleType read token bytes with scan(), which
// silently skips whitespace, and handed the assembled token to
// strconv.ParseFloat, which accepts a far wider grammar than RFC 8259 §6
// (hexadecimal floats, a leading '+', leading zeros, a bare '.', and
// interior whitespace stripped out of the token entirely). That let
// ill-formed inputs such as "[0x1p5]", "[+1]", "[01]", "[.5]", "[1.]",
// "[1 2 3]", "[1 . 5 e 1]", "[tr ue]", and "[nu ll]" canonicalize
// successfully to "[32]", "[1]", "[1]", "[0.5]", "[1]", "[123]", "[15]",
// "[true]", and "[null]" respectively, all of which encoding/json and every
// RFC 8259-conforming parser reject outright.
func TestTransformRejectsMalformedNumbersAndLiterals(t *testing.T) {
	testCases := []struct {
		desc  string
		input string
	}{
		{desc: "HexFloat", input: `[0x1p5]`},
		{desc: "LeadingPlus", input: `[+1]`},
		{desc: "LeadingZero", input: `[01]`},
		{desc: "BareLeadingDot", input: `[.5]`},
		{desc: "BareTrailingDot", input: `[1.]`},
		{desc: "WhitespaceSplitDigits", input: `[1 2 3]`},
		{desc: "WhitespaceSplitFloat", input: `[1 . 5 e 1]`},
		{desc: "WhitespaceSplitTrueLiteral", input: `[tr ue]`},
		{desc: "WhitespaceSplitNullLiteral", input: `[nu ll]`},
	}

	for _, tC := range testCases {
		tC := tC
		t.Run(tC.desc, func(t *testing.T) {
			t.Parallel()
			r := require.New(t)

			_, err := Transform([]byte(tC.input))
			r.Error(err, "Transform should reject a malformed number or literal instead of accepting a wider grammar than RFC 8259")
		})
	}

	// Well-formed numbers and literals, including edge cases the grammar
	// must still accept, must continue to transform normally.
	validCases := []struct {
		desc     string
		input    string
		expected string
	}{
		{desc: "Zero", input: `[0]`, expected: `[0]`},
		{desc: "NegativeZero", input: `[-0]`, expected: `[0]`},
		{desc: "NegativeInteger", input: `[-123]`, expected: `[-123]`},
		{desc: "SimpleFraction", input: `[1.5]`, expected: `[1.5]`},
		{desc: "PositiveExponent", input: `[1.5e+10]`, expected: `[15000000000]`},
		{desc: "NegativeExponent", input: `[1.5E-1]`, expected: `[0.15]`},
		{desc: "TrueLiteral", input: `[true]`, expected: `[true]`},
		{desc: "NullLiteral", input: `[null]`, expected: `[null]`},
	}

	for _, tC := range validCases {
		tC := tC
		t.Run(tC.desc, func(t *testing.T) {
			t.Parallel()
			r := require.New(t)

			transformed, err := Transform([]byte(tC.input))
			r.NoError(err, errorOccurred(fmt.Sprintf("transforming %q", tC.input), err))
			r.Equal(tC.expected, string(transformed))
		})
	}
}

// TestTransformSortsAndDetectsDuplicateObjectKeys checks that object members
// are still correctly sorted into ascending UTF-16 code unit order, and that
// a duplicate key is still detected and rejected, now that parseObject sorts
// members once with sort.Slice instead of maintaining sorted order through
// repeated linked-list insertion.
func TestTransformSortsAndDetectsDuplicateObjectKeys(t *testing.T) {
	r := require.New(t)

	transformed, err := Transform([]byte(`{"c":3,"a":1,"b":2}`))
	r.NoError(err, errorOccurred("transforming an object with out-of-order keys", err))
	r.Equal(`{"a":1,"b":2,"c":3}`, string(transformed))

	_, err = Transform([]byte(`{"a":1,"a":2}`))
	r.Error(err, "Transform should reject an object with a duplicate key")
}

// TestTransformObjectSortIsNotQuadratic guards against a regression of the
// O(n^2) linked-list insertion sort in parseObject, where keys arriving in
// ascending order (a trivially attacker-chosen input) made every new member
// walk the entire list of previously seen members before being appended. A
// single object with many pre-sorted keys therefore took time quadratic in
// the number of members: the reported measurements showed roughly 4x the
// wall-clock time for each doubling of key count, with a 40,000-key, ~560 KB
// object taking around 7.5 seconds of CPU. Sorting once with sort.Slice
// after collecting all members is O(n log n), so a comparably sized object
// should complete in a small fraction of that time.
func TestTransformObjectSortIsNotQuadratic(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping performance regression test in -short mode")
	}
	r := require.New(t)

	const keyCount = 50000
	var b bytes.Buffer
	b.WriteByte('{')
	for i := 0; i < keyCount; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		// Ascending order is the worst case for the old linked-list
		// insertion sort, and is trivially chosen by an attacker.
		fmt.Fprintf(&b, `"k%08d":0`, i)
	}
	b.WriteByte('}')

	start := time.Now()
	_, err := Transform(b.Bytes())
	elapsed := time.Since(start)

	r.NoError(err, errorOccurred("transforming a large object with pre-sorted keys", err))
	// The old O(n^2) implementation took roughly 7.5s for 40,000 keys, and
	// would take well over 10s for 50,000. An O(n log n) sort completes in a
	// small fraction of a second even on slow, shared CI hardware, so this
	// bound leaves generous headroom for the correct implementation while
	// still catching a return to quadratic behavior.
	r.Less(elapsed, 5*time.Second, "sorting %d pre-sorted object keys took %v, which suggests a return to quadratic behavior", keyCount, elapsed)
}

// TestTransformNestingIsNotQuadratic guards against a regression of the
// nesting amplification, where each parse function returned the finished text
// of its own subtree and every enclosing level copied that text into a buffer
// of its own. Total work was then the sum of every subtree size over every
// nesting level, O(n * depth) rather than O(n), which let a small deeply
// nested document allocate gigabytes: a 120 KB payload allocated 1,143 MB and
// a 920 KB payload allocated over nine gigabytes, several seconds of CPU
// apiece. Parsing into a tree and serializing it in one pass writes every
// byte of the output exactly once, which brings the same 120 KB payload down
// to roughly 2 MB.
//
// The assertion is on bytes allocated rather than on elapsed time, because
// allocation is far more stable than wall clock time on shared CI hardware.
// The bound leaves more than an order of magnitude of headroom in both
// directions.
func TestTransformNestingIsNotQuadratic(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping allocation regression test in -short mode")
	}
	r := require.New(t)

	const (
		depth          = maxNestingDepth - 1
		leafBytes      = 100000
		maxAllocatedMB = 100
	)

	payload := make([]byte, 0, depth*2+leafBytes+2)
	for i := 0; i < depth; i++ {
		payload = append(payload, '[')
	}
	payload = append(payload, '"')
	payload = append(payload, bytes.Repeat([]byte("A"), leafBytes)...)
	payload = append(payload, '"')
	for i := 0; i < depth; i++ {
		payload = append(payload, ']')
	}

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	_, err := Transform(payload)
	runtime.ReadMemStats(&after)

	r.NoError(err, errorOccurred("transforming a deeply nested payload", err))

	allocatedMB := float64(after.TotalAlloc-before.TotalAlloc) / (1 << 20)
	r.Less(allocatedMB, float64(maxAllocatedMB),
		"canonicalizing a %d byte payload nested %d deep allocated %.1f MB, which suggests the output is being rebuilt at every nesting level again",
		len(payload), depth, allocatedMB)
}

// TestTransformRejectsInvalidUTF8InString guards against a regression where
// parseQuotedString copied any byte that was not a quote, backslash, or
// ASCII control character straight into the output, including bytes such as
// 0xFF that are not valid at any position in UTF-8. RFC 8785 §3.2.4 defines
// the canonical output as UTF-8 encoded text, so input that is not
// well-formed UTF-8 must be rejected rather than passed through, which would
// otherwise leave the "canonical" output itself not valid UTF-8.
func TestTransformRejectsInvalidUTF8InString(t *testing.T) {
	testCases := []struct {
		desc string
		// input is given as hex so that the invalid byte sequence can be
		// expressed exactly, independent of how Go source would interpret it.
		inputHex string
	}{
		// ["<0xFF>"]: 0xFF is not a valid UTF-8 byte at any position.
		{desc: "LoneInvalidByte", inputHex: "5b22ff225d"},
		// ["<0xC0><0x80>"]: an overlong two-byte encoding of NUL.
		{desc: "OverlongEncoding", inputHex: "5b22c080225d"},
		// ["<0xED><0xA0><0x80>"]: a CESU-8/WTF-8 style encoding of the
		// surrogate code point U+D800, which RFC 3629 explicitly excludes
		// from valid UTF-8.
		{desc: "SurrogateEncodedAsUTF8", inputHex: "5b22eda080225d"},
	}

	for _, tC := range testCases {
		tC := tC
		t.Run(tC.desc, func(t *testing.T) {
			t.Parallel()
			r := require.New(t)

			input, err := hex.DecodeString(tC.inputHex)
			r.NoError(err, "test fixture hex should decode cleanly")

			_, err = Transform(input)
			r.Error(err, "Transform should reject a string containing a byte sequence that is not valid UTF-8")
		})
	}

	// A genuine multi-byte UTF-8 character must still pass through unchanged.
	r := require.New(t)
	transformed, err := Transform([]byte("[\"caf\xc3\xa9\"]"))
	r.NoError(err, errorOccurred("transforming a string containing valid multi-byte UTF-8", err))
	r.Equal("[\"caf\xc3\xa9\"]", string(transformed))
}

// TestTransformAcceptsWhitespaceAroundTopLevelScalar guards against a
// regression where parseEntry handed the entire input buffer to parseLiteral
// for a top level literal or number, which made any surrounding
// insignificant whitespace part of the token itself. Documents as ordinary
// as "true\n", the output of almost any text editor or file writer, were
// rejected even though RFC 8259 permits whitespace around the top level
// value. Whitespace around a top level object, array, or string was already
// handled correctly, so only bare scalars were affected.
func TestTransformAcceptsWhitespaceAroundTopLevelScalar(t *testing.T) {
	accepted := []struct {
		desc     string
		input    string
		expected string
	}{
		{desc: "TrailingNewline", input: "true\n", expected: "true"},
		{desc: "LeadingSpace", input: " true", expected: "true"},
		{desc: "TrailingSpace", input: "true ", expected: "true"},
		{desc: "NumberTrailingNewline", input: "42\n", expected: "42"},
		{desc: "NumberLeadingSpace", input: " 42", expected: "42"},
		{desc: "NullTrailingTab", input: "null\t", expected: "null"},
		{desc: "CarriageReturnAndNewline", input: "1.5e-7\r\n", expected: "1.5e-7"},
		{desc: "SurroundedByMixedWhitespace", input: "  \t\r\n false \t\r\n ", expected: "false"},
		{desc: "NoWhitespaceAtAll", input: "true", expected: "true"},
	}

	for _, tC := range accepted {
		tC := tC
		t.Run(tC.desc, func(t *testing.T) {
			t.Parallel()
			r := require.New(t)

			transformed, err := Transform([]byte(tC.input))
			r.NoError(err, errorOccurred(fmt.Sprintf("transforming %q", tC.input), err))
			r.Equal(tC.expected, string(transformed))
		})
	}

	// Accepting surrounding whitespace must not weaken rejection of a
	// document that carries anything else beside the top level value.
	rejected := []struct {
		desc  string
		input string
	}{
		{desc: "TwoValues", input: "true false"},
		{desc: "LiteralWithSuffix", input: "truex"},
		{desc: "NumberWithSuffix", input: "42abc"},
		{desc: "ValueThenJunk", input: "1 x"},
		{desc: "ArrayThenJunk", input: "[1] x"},
		{desc: "UnclosedArray", input: "[1"},
		{desc: "UnclosedObject", input: `{"a":1`},
		{desc: "UnclosedNestedArray", input: "[[1]"},
		{desc: "BareMinus", input: "-"},
		{desc: "BareDot", input: "."},
		{desc: "WhitespaceOnly", input: " \t\n"},
	}

	for _, tC := range rejected {
		tC := tC
		t.Run(tC.desc, func(t *testing.T) {
			t.Parallel()
			r := require.New(t)

			_, err := Transform([]byte(tC.input))
			r.Error(err, "Transform should still reject %q", tC.input)
		})
	}
}

// TestErrorMessagesAreBoundedAndQuoted checks that fragments of the input
// document copied into an error message are both length bounded and quoted.
// Error strings from a canonicalizer running on untrusted input are
// routinely written to logs, so an unbounded fragment lets one request write
// megabytes of attacker chosen data to a log, and an unquoted fragment lets
// that data carry newlines or terminal escape sequences into it.
func TestErrorMessagesAreBoundedAndQuoted(t *testing.T) {
	r := require.New(t)

	// A two megabyte malformed token must not produce a two megabyte error.
	_, err := Transform([]byte("[1." + strings.Repeat("9", 2000000) + ".5]"))
	r.Error(err)
	r.Less(len(err.Error()), 256, "error message should stay bounded, got %d bytes", len(err.Error()))

	// The same holds for a syntactically valid but out of range number,
	// whose error would otherwise come straight from strconv and embed the
	// whole token.
	_, err = Transform([]byte("[" + strings.Repeat("9", 500000) + "e999]"))
	r.Error(err)
	r.Less(len(err.Error()), 256, "error message should stay bounded, got %d bytes", len(err.Error()))

	// A key carrying a newline and a terminal escape sequence must not reach
	// an error string unescaped.
	_, err = Transform([]byte(`{"a\u000aforged log line\u001b[31m":1,"a\u000aforged log line\u001b[31m":2}`))
	r.Error(err)
	r.NotContains(err.Error(), "\n", "a raw newline must not be copied into an error message")
	r.NotContains(err.Error(), "\x1b", "a raw escape character must not be copied into an error message")
}
