//
//  Copyright 2006-2019 WebPKI.org (http://webpki.org).
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//      https://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.
//

// This program verifies the JSON canonicalizer using a test suite
// containing sample data and expected output

package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/gowebpki/jcs"
)

func check(e error) {
	if e != nil {
		panic(e)
	}
}

var testdata string

var failures = 0

func read(fileName string, directory string) []byte {
	data, err := os.ReadFile(filepath.Join(filepath.Join(testdata, directory), fileName))
	check(err)
	return data
}

/*
locateTestData - Work out where the canonicalization test vectors live.

An explicit command line argument wins. Otherwise the directory is derived
from this source file's compile time path, which is correct when the tool is
run from a checkout with "go run ./test/verify-canonicalization". That
derivation cannot work for an installed binary, or for one built with
-trimpath, because the recorded path is then either another machine's
directory or a module relative path such as
"github.com/gowebpki/jcs/test/verify-canonicalization". Passing the directory
as an argument is the supported way to run those.
*/
func locateTestData() string {
	if len(os.Args) > 1 {
		return os.Args[1]
	}

	// thisFile is <repository>/test/verify-canonicalization/verify-canonicalization.go,
	// so three parent steps reach the repository root, where testdata lives.
	_, thisFile, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(filepath.Dir(filepath.Dir(thisFile))), "testdata")
}

func verify(fileName string) {
	actual, err := jcs.Transform(read(fileName, "input"))
	check(err)
	recycled, err2 := jcs.Transform(actual)
	check(err2)
	expected := read(fileName, "output")
	utf8InHex := "\nFile: " + fileName
	byteCount := 0
	next := false
	for _, b := range actual {
		if byteCount%32 == 0 {
			utf8InHex = utf8InHex + "\n"
			next = false
		}
		byteCount++
		if next {
			utf8InHex = utf8InHex + " "
		}
		next = true
		utf8InHex = utf8InHex + fmt.Sprintf("%02x", b)
	}
	fmt.Println(utf8InHex + "\n")
	if !bytes.Equal(actual, expected) || !bytes.Equal(actual, recycled) {
		failures++
		fmt.Println("THE TEST ABOVE FAILED!")
	}
}

func main() {
	testdata = locateTestData()
	fmt.Println(testdata)
	files, err := os.ReadDir(filepath.Join(testdata, "input"))
	check(err)
	for _, file := range files {
		verify(file.Name())
	}
	if failures == 0 {
		fmt.Println("All tests succeeded!")
		return
	}
	// Exit non zero so that the tool can be used from a script or a CI job.
	fmt.Printf("\n****** ERRORS: %d *******\n", failures)
	os.Exit(1)
}
