// Copyright 2021 Bret Jordan, All rights reserved.
// Copyright 2006-2019 WebPKI.org (http://webpki.org).
//
// Use of this source code is governed by an Apache 2.0 license that can be
// found in the LICENSE file in the root of the source tree.

package jcs

import (
	"errors"
	"math"
	"strconv"
	"strings"
)

const invalidPattern uint64 = 0x7ff0000000000000

// NumberToJSON converts numbers in IEEE-754 double precision into the
// format specified for JSON in EcmaScript Version 6 and forward.
// The core application for this is canonicalization per RFC 8785:
func NumberToJSON(ieeeF64 float64) (res string, err error) {
	ieeeU64 := math.Float64bits(ieeeF64)

	// Special case: NaN and Infinity are invalid in JSON
	if (ieeeU64 & invalidPattern) == invalidPattern {
		return "null", errors.New("Invalid JSON number: " + strconv.FormatUint(ieeeU64, 16))
	}

	// Special case: eliminate "-0" as mandated by the ES6-JSON/JCS specifications
	if ieeeF64 == 0 { // Right, this line takes both -0 and 0
		return "0", nil
	}

	// Deal with the sign separately
	var sign string = ""
	if ieeeF64 < 0 {
		ieeeF64 = -ieeeF64
		sign = "-"
	}

	// ES6 has a unique "g" format
	var format byte = 'e'
	if ieeeF64 < 1e+21 && ieeeF64 >= 1e-6 {
		format = 'f'
	}

	// The following should (in "theory") do the trick:
	es6Formatted := strconv.FormatFloat(ieeeF64, format, -1, 64)

	// Unfortunately Go version 1.11.4 is a bit buggy with respect to
	// rounding for -1 precision which is dealt with below.
	// https://github.com/golang/go/issues/29491
	exponent := strings.IndexByte(es6Formatted, 'e')
	if exponent > 0 {
		gform := strconv.FormatFloat(ieeeF64, 'g', 17, 64)
		if len(gform) == len(es6Formatted) {
			// "g" occasionally produces another result which also is the correct one
			es6Formatted = gform
		}
		// Go outputs "1e+09" which must be rewritten as "1e+9"
		if es6Formatted[exponent+2] == '0' {
			es6Formatted = es6Formatted[:exponent+2] + es6Formatted[exponent+3:]
		}
	} else if strings.IndexByte(es6Formatted, '.') < 0 && len(es6Formatted) >= 12 {
		i := len(es6Formatted)
		for es6Formatted[i-1] == '0' {
			i--
		}
		if i != len(es6Formatted) {
			fix := strconv.FormatFloat(ieeeF64, 'f', 0, 64)
			if fix[i] >= '5' {
				// "f" with precision 0 occasionally produces another result which also is
				// the correct one although it must be rounded to match the -1 precision
				// (which fortunately seems to be correct with respect to trailing zeroes)
				es6Formatted = fix[:i-1] + string(fix[i-1]+1) + es6Formatted[i:]
			}
		}
	}
	return sign + es6Formatted, nil
}
