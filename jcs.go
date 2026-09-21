// Copyright 2021-2026 Bret Jordan & Benedikt Thoma, All rights reserved.
// Copyright 2006-2019 WebPKI.org (http://webpki.org).
//
// Use of this source code is governed by an Apache 2.0 license that can be
// found in the LICENSE file in the root of the source tree.

// Package jcs transforms UTF-8 JSON data into a canonicalized version according RFC 8785
package jcs

import (
	"bytes"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// nodeKind identifies which of the node fields carries the parsed value.
type nodeKind uint8

const (
	// nodeScalar is a literal, a number, or a string, held as the finished
	// canonical text of that value.
	nodeScalar nodeKind = iota
	// nodeArray is an array, held as its elements in document order.
	nodeArray
	// nodeObject is an object, held as its members already sorted.
	nodeObject
)

/*
node - One parsed JSON value.

Parsing and serialization are deliberately separate passes. Parsing builds a
tree of these nodes, and a single serialization pass then writes the whole
tree into one output buffer.

An earlier design had each parse function return the finished text of its own
subtree, which every enclosing level then copied into a buffer of its own.
That made the total work the sum of every subtree size over every nesting
level, which is O(n * depth) rather than O(n), and it gave an attacker an
amplification factor bounded only by the nesting limit: a 920 KB document
nested to the limit allocated over nine gigabytes and burned several seconds
of CPU. Writing each byte of the output exactly once removes that term
entirely.
*/
type node struct {
	kind     nodeKind
	text     string          // nodeScalar
	elements []node          // nodeArray
	members  []nameValueType // nodeObject
}

/*
appendElement and appendMember - Grow a large collection of parsed children by
doubling rather than by the runtime's default policy.

The runtime doubles a slice's capacity while it is small, and then, past a few
hundred elements, switches to growing it by roughly a quarter at a time.
Filling a large slice by repeated append therefore allocates about five times
the size of the finished slice. The number of children in an array or an
object is chosen by whoever supplies the document, which makes that overhead
attacker controlled: a flat array of 400,000 elements allocated 178 MB where
the finished slice needs 29 MB.

Doubling is taken over only once the slice is already large, because below
that point the runtime is doing the same thing and doing it without the
over allocation that a fixed starting capacity would impose on the small
containers that make up most real documents.

These are two nearly identical functions rather than one generic function on
purpose, so that the package keeps building on Go releases older than 1.18.
*/
const growthTakeoverCapacity = 256

func appendElement(elements []node, element node) []node {
	if len(elements) == cap(elements) && cap(elements) >= growthTakeoverCapacity {
		grown := make([]node, len(elements), cap(elements)*2)
		copy(grown, elements)
		elements = grown
	}
	return append(elements, element)
}

func appendMember(members []nameValueType, member nameValueType) []nameValueType {
	if len(members) == cap(members) && cap(members) >= growthTakeoverCapacity {
		grown := make([]nameValueType, len(members), cap(members)*2)
		copy(grown, members)
		members = grown
	}
	return append(members, member)
}

/*
nameValueType - One member of a JSON object.

value is held behind a pointer deliberately. Sorting moves these structs
around, and sort.Slice swaps them through a reflect based swapper that copies
the whole struct each time, so an object with many members is sensitive to how
wide this struct is. A pointer keeps it narrower than an inline node would,
which matters because the number of members in an object is attacker chosen.
*/
type nameValueType struct {
	name    string
	sortKey []uint16
	value   *node
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

// maxErrorTokenLength bounds how much of the input document may be copied
// into an error message.
const maxErrorTokenLength = 32

// forError renders a fragment of the input document for inclusion in an
// error message. It quotes the fragment and truncates it to
// maxErrorTokenLength bytes. Both matter for a canonicalizer that runs on
// untrusted input: error strings are routinely written to logs, so an
// unbounded fragment would let a single request write megabytes of attacker
// chosen data to a log, an unquoted fragment would let that data carry
// newlines or terminal escape sequences into the log, and either way the
// content of a document being signed should not be copied wholesale into
// places the document itself was never meant to reach.
func forError(value string) string {
	if len(value) > maxErrorTokenLength {
		return fmt.Sprintf("%q (truncated from %d bytes)",
			value[:maxErrorTokenLength], len(value))
	}
	return fmt.Sprintf("%q", value)
}

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

	root, err := j.parseEntry()
	if err != nil {
		return nil, err
	}

	for j.index < len(j.jsonData) {
		if !j.isWhiteSpace(j.jsonData[j.index]) {
			return nil, errors.New("Improperly terminated JSON object")
		}
		j.index++
	}

	// Serialize the parsed tree in a single pass into one buffer, so that
	// every byte of the canonical output is written exactly once. The input
	// length is only a starting hint: canonical output is usually smaller
	// than its input, because insignificant whitespace is dropped, but a
	// number such as 1e20 does expand on the way out.
	var canonical bytes.Buffer
	canonical.Grow(len(jsonData))
	j.writeNode(&canonical, root)
	return canonical.Bytes(), nil
}

/*
writeNode - Append the canonical text of one node, and of everything below
it, to out.

Recursion here is bounded by the same maxNestingDepth that bounded parsing,
because the tree cannot be deeper than the input that produced it.
*/
func (j *jcsData) writeNode(out *bytes.Buffer, n node) {
	switch n.kind {
	case nodeArray:
		out.WriteByte('[')
		for i := range n.elements {
			if i > 0 {
				out.WriteByte(',')
			}
			j.writeNode(out, n.elements[i])
		}
		out.WriteByte(']')

	case nodeObject:
		out.WriteByte('{')
		for i := range n.members {
			if i > 0 {
				out.WriteByte(',')
			}
			out.WriteString(j.decorateString(n.members[i].name))
			out.WriteByte(':')
			j.writeNode(out, *n.members[i].value)
		}
		out.WriteByte('}')

	default:
		out.WriteString(n.text)
	}
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
		return fmt.Errorf("Expected %q but got %q", rune(expected), rune(c))
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
func (j *jcsData) parseEntry() (node, error) {
	_, err := j.scan()
	if err != nil {
		return node{}, err
	}
	j.index--

	// Every top level value, a bare literal or number included, is parsed by
	// the ordinary element parser. Handing the entire buffer to parseLiteral
	// instead, as this function used to, made any insignificant whitespace
	// around a top level scalar part of the token itself, so that ordinary
	// documents such as "true\n" or " 42" were rejected even though RFC 8259
	// permits whitespace around the top level value. Transform checks for
	// trailing content once the value has been parsed.
	return j.parseElement()
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
				return "", fmt.Errorf("Unexpected escape: %q", string([]byte{'\\', c}))
			}
		} else if c < 0x80 {
			// An ordinary ASCII character.
			// Note that properly formatted UTF-8 never clashes with ASCII
			// making byte per byte search for ASCII break characters work
			// as expected.
			rawString.WriteByte(c)
		} else {
			// The lead byte of a multi-byte UTF-8 sequence. RFC 8785 §3.2.4
			// requires the canonical output to be valid UTF-8, so the
			// sequence starting here is decoded and validated rather than
			// copied through byte for byte: a byte such as 0xFF is not
			// valid at any position in UTF-8 and must be rejected, not
			// passed along into the output unchanged.
			j.index--
			r, size := utf8.DecodeRune(j.jsonData[j.index:])
			if r == utf8.RuneError && size <= 1 {
				return "", fmt.Errorf("Invalid UTF-8 sequence at byte 0x%02x", c)
			}
			rawString.Write(j.jsonData[j.index : j.index+size])
			j.index += size
		}
	}

	return rawString.String(), nil
}

func (j *jcsData) parseSimpleType() (node, error) {
	var token strings.Builder

	j.index--

	for {
		// End of input terminates a top level literal or number that is not
		// followed by any structural character, such as the whole document
		// "42". An unterminated array or object is still rejected, because
		// the caller goes on to fail on the missing ']' or '}'.
		if j.index >= len(j.jsonData) {
			break
		}

		c, err := j.nextChar()
		if err != nil {
			return node{}, err
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
		return node{}, errors.New("Missing argument")
	}

	text, err := parseLiteral(token.String())
	if err != nil {
		return node{}, err
	}

	return node{kind: nodeScalar, text: text}, nil
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
		return "", fmt.Errorf("Invalid literal or number: %s", forError(value))
	}

	ieeeF64, err := strconv.ParseFloat(value, 64)
	if err != nil {
		// The error strconv returns embeds the entire token, so it is
		// replaced here with a bounded message. A syntactically valid JSON
		// number may be arbitrarily long, and only a value out of range for
		// an IEEE 754 double can reach this point.
		return "", fmt.Errorf("Number out of range: %s", forError(value))
	}

	value, err = NumberToJSON(ieeeF64)
	if err != nil {
		return "", err
	}

	return value, nil
}

func (j *jcsData) parseElement() (node, error) {
	c, err := j.scan()
	if err != nil {
		return node{}, err
	}

	switch c {
	case '{':
		return j.parseObject()
	case '"':
		str, err := j.parseQuotedString()
		if err != nil {
			return node{}, err
		}
		return node{kind: nodeScalar, text: j.decorateString(str)}, nil
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

func (j *jcsData) parseArray() (node, error) {
	j.depth++
	defer func() { j.depth-- }()
	if j.depth > maxNestingDepth {
		return node{}, fmt.Errorf("Maximum nesting depth of %d exceeded", maxNestingDepth)
	}

	// Element order in an array is significant and is never changed, so the
	// elements are simply collected in document order.
	elements := []node{}
	var next bool

	for {
		c, err := j.peek()
		if err != nil {
			return node{}, err
		}

		if c == ']' {
			j.index++
			break
		}

		if next {
			err = j.scanFor(',')
			if err != nil {
				return node{}, err
			}
		} else {
			next = true
		}

		element, err := j.parseElement()
		if err != nil {
			return node{}, err
		}
		elements = appendElement(elements, element)
	}

	return node{kind: nodeArray, elements: elements}, nil
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

func (j *jcsData) parseObject() (node, error) {
	j.depth++
	defer func() { j.depth-- }()
	if j.depth > maxNestingDepth {
		return node{}, fmt.Errorf("Maximum nesting depth of %d exceeded", maxNestingDepth)
	}

	nameValues := []nameValueType{}
	var next bool = false
	for {
		c, err := j.peek()
		if err != nil {
			return node{}, err
		}

		if c == '}' {
			// advance index because of peeked '}'
			j.index++
			break
		}

		if next {
			err = j.scanFor(',')
			if err != nil {
				return node{}, err
			}
		}
		next = true

		err = j.scanFor('"')
		if err != nil {
			return node{}, err
		}
		rawUTF8, err := j.parseQuotedString()
		if err != nil {
			return node{}, err
		}
		// Sort keys on UTF-16 code units
		// Since UTF-8 doesn't have endianess this is just a value transformation
		// In the Go case the transformation is UTF-8 => UTF-32 => UTF-16
		sortKey := utf16.Encode([]rune(rawUTF8))
		err = j.scanFor(':')
		if err != nil {
			return node{}, err
		}

		element, err := j.parseElement()
		if err != nil {
			return node{}, err
		}
		value := element
		nameValues = appendMember(nameValues, nameValueType{rawUTF8, sortKey, &value})
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
			return node{}, fmt.Errorf("Duplicate key: %s", forError(nameValues[i].name))
		}
	}

	// The members are sorted here, at parse time, but they are not written
	// out here. Serialization of the whole tree happens in one later pass.
	return node{kind: nodeObject, members: nameValues}, nil
}
