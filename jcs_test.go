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
