// Copyright 2021 Bret Jordan & Benedikt Thoma, All rights reserved.
// Copyright 2006-2019 WebPKI.org (http://webpki.org).
//
// Use of this source code is governed by an Apache 2.0 license that can be
// found in the LICENSE file in the root of the source tree.

// Package jcs transforms UTF-8 JSON data into a canonicalized version according RFC 8785
package jcs

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
)

type nameValueType struct {
	name    string
	sortKey []uint16
	value   string
}

type jcsData struct {
	// JSON data MUST be UTF-8 encoded
	jsonData []byte
	// Current pointer in jsonData
	index int
	// Current nesting depth of arrays and objects
	depth int
}

// maxNestingDepth bounds the recursion depth of parseElement, parseArray, and
// parseObject. Without a bound, a payload consisting of many nested arrays or
// objects (for example a long run of '[' characters) grows the goroutine call
// stack until the Go runtime aborts the process with a fatal, unrecoverable
// stack overflow. The value matches the nesting limit used by encoding/json.
const maxNestingDepth = 10000

// JSON standard escapes (modulo \u)
var (
	asciiEscapes  = []byte{'\\', '"', 'b', 'f', 'n', 'r', 't'}
	binaryEscapes = []byte{'\\', '"', '\b', '\f', '\n', '\r', '\t'}
)

// JSON literals
var literals = []string{"true", "false", "null"}

// UTF-16 surrogate ranges, used to validate \u escape pairs. A valid
// surrogate pair is a high surrogate (the first code unit) followed by a low
// surrogate (the second code unit); any other pairing is ill-formed and must
// be rejected rather than silently decoded to U+FFFD.
const (
	highSurrogateMin = 0xD800
	highSurrogateMax = 0xDBFF
	lowSurrogateMin  = 0xDC00
	lowSurrogateMax  = 0xDFFF
)

// Transform converts raw JSON data from a []byte array into a canonicalized version according RFC 8785
func Transform(jsonData []byte) ([]byte, error) {
	if jsonData == nil {
		return nil, errors.New("No JSON data provided")
	}

	// Create a JCS Data struct to store the JSON Data and the index.
	var jd jcsData
	jd.jsonData = jsonData
	j := &jd

	transformed, err := j.parseEntry()
	if err != nil {
		return nil, err
	}

	for j.index < len(j.jsonData) {
		if !j.isWhiteSpace(j.jsonData[j.index]) {
			return nil, errors.New("Improperly terminated JSON object")
		}
		j.index++
	}
	return []byte(transformed), err
}

func (j *jcsData) isWhiteSpace(c byte) bool {
	return c == 0x20 || c == 0x0a || c == 0x0d || c == 0x09
}

func (j *jcsData) nextChar() (byte, error) {
	if j.index < len(j.jsonData) {
		c := j.jsonData[j.index]
		if c > 0x7f {
			return 0, errors.New("Unexpected non-ASCII character")
		}
		j.index++
		return c, nil
	}
	return 0, errors.New("Unexpected EOF reached")
}

// scan advances index on jsonData to the first non whitespace character and returns it.
func (j *jcsData) scan() (byte, error) {
	for {
		c, err := j.nextChar()
		if err != nil {
			return 0, err
		}

		if j.isWhiteSpace(c) {
			continue
		}

		return c, nil
	}
}

func (j *jcsData) scanFor(expected byte) error {
	c, err := j.scan()
	if err != nil {
		return err
	}
	if c != expected {
		return fmt.Errorf("Expected %s but got %s", string(expected), string(c))
	}
	return nil
}

func (j *jcsData) getUEscape() (rune, error) {
	start := j.index
	for i := 0; i < 4; i++ {
		_, err := j.nextChar()
		if err != nil {
			return 0, err
		}
	}

	u16, err := strconv.ParseUint(string(j.jsonData[start:j.index]), 16, 64)
	if err != nil {
		return 0, err
	}
	return rune(u16), nil
}

func (j *jcsData) decorateString(rawUTF8 string) string {
	var quotedString strings.Builder
	quotedString.WriteByte('"')

CoreLoop:
	for _, c := range []byte(rawUTF8) {
		// Is this within the JSON standard escapes?
		for i, esc := range binaryEscapes {
			if esc == c {
				quotedString.WriteByte('\\')
				quotedString.WriteByte(asciiEscapes[i])

				continue CoreLoop
			}
		}
		if c < 0x20 {
			// Other ASCII control characters must be escaped with \uhhhh
			quotedString.WriteString(fmt.Sprintf("\\u%04x", c))
		} else {
			quotedString.WriteByte(c)
		}
	}
	quotedString.WriteByte('"')

	return quotedString.String()
}

// parseEntry is the entrypoint into the parsing control flow
func (j *jcsData) parseEntry() (string, error) {
	c, err := j.scan()
	if err != nil {
		return "", err
	}
	j.index--

	switch c {
	case '{', '"', '[':
		return j.parseElement()
	default:
		value, err := parseLiteral(string(j.jsonData))
		if err != nil {
			return "", err
		}

		j.index = len(j.jsonData)
		return value, nil
	}
}

func (j *jcsData) parseQuotedString() (string, error) {
	var rawString strings.Builder

CoreLoop:
	for {
		var c byte
		if j.index < len(j.jsonData) {
			c = j.jsonData[j.index]
			j.index++
		} else {
			return "", errors.New("Unexpected EOF reached")
		}

		if c == '"' {
			break
		}

		if c < ' ' {
			return "", errors.New("Unterminated string literal")
		} else if c == '\\' {
			// Escape sequence
			c, err := j.nextChar()
			if err != nil {
				return "", err
			}

			if c == 'u' {
				// The \u escape
				firstUTF16, err := j.getUEscape()
				if err != nil {
					return "", err
				}

				if utf16.IsSurrogate(firstUTF16) {
					// Only a high surrogate may begin a pair. A lone low
					// surrogate here is ill-formed and RFC 8785 requires
					// that it be rejected rather than decoded.
					if firstUTF16 < highSurrogateMin || firstUTF16 > highSurrogateMax {
						return "", fmt.Errorf("Invalid high surrogate: \\u%04x", firstUTF16)
					}

					// If the first UTF-16 code unit has a certain value there must be
					// another succeeding UTF-16 code unit as well
					backslash, err := j.nextChar()
					if err != nil {
						return "", err
					}
					u, err := j.nextChar()
					if err != nil {
						return "", err
					}

					if backslash != '\\' || u != 'u' {
						return "", errors.New("Missing surrogate")
					}

					// Output the UTF-32 code point as UTF-8
					uEscape, err := j.getUEscape()
					if err != nil {
						return "", err
					}

					// The second code unit must be a low surrogate. Any other
					// value is an invalid pairing that utf16.DecodeRune would
					// otherwise silently turn into U+FFFD.
					if uEscape < lowSurrogateMin || uEscape > lowSurrogateMax {
						return "", fmt.Errorf("Invalid low surrogate: \\u%04x", uEscape)
					}
					rawString.WriteRune(utf16.DecodeRune(firstUTF16, uEscape))

				} else {
					// Single UTF-16 code identical to UTF-32.  Output as UTF-8
					rawString.WriteRune(firstUTF16)
				}
			} else if c == '/' {
				// Benign but useless escape
				rawString.WriteByte('/')
			} else {
				// The JSON standard escapes
				for i, esc := range asciiEscapes {
					if esc == c {
						rawString.WriteByte(binaryEscapes[i])
						continue CoreLoop
					}
				}
				return "", fmt.Errorf("Unexpected escape: \\%s", string(c))
			}
		} else {
			// Just an ordinary ASCII character alternatively a UTF-8 byte
			// outside of ASCII.
			// Note that properly formatted UTF-8 never clashes with ASCII
			// making byte per byte search for ASCII break characters work
			// as expected.
			rawString.WriteByte(c)
		}
	}

	return rawString.String(), nil
}

func (j *jcsData) parseSimpleType() (string, error) {
	var token strings.Builder

	j.index--

	// no condition is needed here.
	// if the buffer reaches EOF nextChar returns an error, or we terminate because the
	// json simple type terminates
	for {
		c, err := j.nextChar()
		if err != nil {
			return "", err
		}

		// A literal or number is terminated by a structural character or by
		// whitespace. Using nextChar (rather than scan, which silently skips
		// whitespace) and stopping on whitespace here means interior spaces,
		// tabs, or newlines are never stripped out of the middle of a token:
		// "1 2 3" and "tr ue" are left as ill-formed instead of collapsing
		// into "123" and "true".
		if c == ',' || c == ']' || c == '}' || j.isWhiteSpace(c) {
			j.index--
			break
		}

		token.WriteByte(c)
	}

	if token.Len() == 0 {
		return "", errors.New("Missing argument")
	}

	return parseLiteral(token.String())
}

// numberPattern is the RFC 8259 §6 number grammar:
//
//	number = [ "-" ] int [ frac ] [ exp ]
//	int    = "0" / ( digit1-9 *DIGIT )
//	frac   = "." 1*DIGIT
//	exp    = ("e" / "E") [ "-" / "+" ] 1*DIGIT
//
// strconv.ParseFloat accepts a considerably wider grammar than this (hex
// floating-point literals, a leading '+', leading zeros, digit-separator
// underscores, and a bare leading or trailing '.'), so a token must match
// this pattern before it is handed to ParseFloat.
var numberPattern = regexp.MustCompile(`^-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?$`)

func parseLiteral(value string) (string, error) {
	// Is it a JSON literal?
	for _, literal := range literals {
		if literal == value {
			return literal, nil
		}
	}

	// Apparently not a literal, so we assume that it is a I-JSON number.
	// Reject anything that is not a well-formed JSON number (and is not one
	// of the known literals either) before consulting strconv.ParseFloat.
	if !numberPattern.MatchString(value) {
		return "", fmt.Errorf("Invalid literal or number: %s", value)
	}

	ieeeF64, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return "", err
	}

	value, err = NumberToJSON(ieeeF64)
	if err != nil {
		return "", err
	}

	return value, nil
}

func (j *jcsData) parseElement() (string, error) {
	c, err := j.scan()
	if err != nil {
		return "", err
	}

	switch c {
	case '{':
		return j.parseObject()
	case '"':
		str, err := j.parseQuotedString()
		if err != nil {
			return "", err
		}
		return j.decorateString(str), nil
	case '[':
		return j.parseArray()
	default:
		return j.parseSimpleType()
	}
}

func (j *jcsData) peek() (byte, error) {
	c, err := j.scan()
	if err != nil {
		return 0, err
	}

	j.index--
	return c, nil
}

func (j *jcsData) parseArray() (string, error) {
	j.depth++
	defer func() { j.depth-- }()
	if j.depth > maxNestingDepth {
		return "", fmt.Errorf("Maximum nesting depth of %d exceeded", maxNestingDepth)
	}

	var arrayData strings.Builder
	var next bool

	arrayData.WriteByte('[')

	for {
		c, err := j.peek()
		if err != nil {
			return "", err
		}

		if c == ']' {
			j.index++
			break
		}

		if next {
			err = j.scanFor(',')
			if err != nil {
				return "", err
			}
			arrayData.WriteByte(',')
		} else {
			next = true
		}

		element, err := j.parseElement()
		if err != nil {
			return "", err
		}
		arrayData.WriteString(element)
	}

	arrayData.WriteByte(']')
	return arrayData.String(), nil
}

// compareSortKeys lexicographically compares two UTF-16 sort keys, returning
// a negative number if a precedes b, zero if they are equal, and a positive
// number if a succeeds b. It is used to sort object members once, in
// O(n log n), rather than the earlier approach of scanning a linked list from
// the front for every new member, which was O(n) per insertion (O(n^2)
// overall) and let an object with many keys already in ascending order (a
// trivially attacker-chosen input) burn CPU quadratically in the number of
// members.
func compareSortKeys(a, b []uint16) int {
	minLength := len(a)
	if minLength > len(b) {
		minLength = len(b)
	}
	for q := 0; q < minLength; q++ {
		diff := int(a[q]) - int(b[q])
		if diff != 0 {
			return diff
		}
	}
	// Equal up to minLength, so the shorter key precedes the longer one.
	return len(a) - len(b)
}

func (j *jcsData) parseObject() (string, error) {
	j.depth++
	defer func() { j.depth-- }()
	if j.depth > maxNestingDepth {
		return "", fmt.Errorf("Maximum nesting depth of %d exceeded", maxNestingDepth)
	}

	var nameValues []nameValueType
	var next bool = false
	for {
		c, err := j.peek()
		if err != nil {
			return "", err
		}

		if c == '}' {
			// advance index because of peeked '}'
			j.index++
			break
		}

		if next {
			err = j.scanFor(',')
			if err != nil {
				return "", err
			}
		}
		next = true

		err = j.scanFor('"')
		if err != nil {
			return "", err
		}
		rawUTF8, err := j.parseQuotedString()
		if err != nil {
			return "", err
		}
		// Sort keys on UTF-16 code units
		// Since UTF-8 doesn't have endianess this is just a value transformation
		// In the Go case the transformation is UTF-8 => UTF-32 => UTF-16
		sortKey := utf16.Encode([]rune(rawUTF8))
		err = j.scanFor(':')
		if err != nil {
			return "", err
		}

		element, err := j.parseElement()
		if err != nil {
			return "", err
		}
		nameValues = append(nameValues, nameValueType{rawUTF8, sortKey, element})
	}

	// Sort all members once, in O(n log n), rather than maintaining sorted
	// order incrementally as each member is parsed.
	sort.Slice(nameValues, func(i, k int) bool {
		return compareSortKeys(nameValues[i].sortKey, nameValues[k].sortKey) < 0
	})

	// A duplicate key sorts adjacent to itself, so a single linear pass over
	// the now-sorted members is enough to detect it.
	for i := 1; i < len(nameValues); i++ {
		if compareSortKeys(nameValues[i-1].sortKey, nameValues[i].sortKey) == 0 {
			return "", fmt.Errorf("Duplicate key: %s", nameValues[i].name)
		}
	}

	// Now everything is sorted so we can properly serialize the object
	var objectData strings.Builder
	objectData.WriteByte('{')
	next = false
	for _, nameValue := range nameValues {
		if next {
			objectData.WriteByte(',')
		}
		next = true
		objectData.WriteString(j.decorateString(nameValue.name))
		objectData.WriteByte(':')
		objectData.WriteString(nameValue.value)
	}
	objectData.WriteByte('}')
	return objectData.String(), nil
}
