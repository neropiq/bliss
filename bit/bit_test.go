// Copyright (c) 2018 Aidos Developer

// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

//This code includes codes from https://rosettacode.org/wiki/Bitwise_IO#Go

// Package bit provides bit-wise IO to an io.Writer and from an io.Reader.
package bit

import (
	"bytes"
	"log"
	"testing"
)

func TestExampleWriter(t *testing.T) {
	var buf bytes.Buffer
	bw := NewWriter(&buf)
	if err := bw.Write(0xff, 4); err != nil { // Writes        1111
		t.Error(err)
	}
	if err := bw.Write(0x00, 1); err != nil { //             0
		t.Error(err)
	}
	if err := bw.Write(0x13, 5); err != nil { //       10 011
		t.Error(err)
	}
	// Close will flush with zero bits, in this case
	//                  0000 00
	if err := bw.Close(); err != nil {
		log.Fatal(err)
	}
	if !bytes.Equal(buf.Bytes(), []byte{0x6f, 0x02}) {
		t.Error("incorrect")
	}
	t.Logf("%08b", buf.Bytes())
}

func TestExample(t *testing.T) {
	message := "This is a test."
	t.Logf("%q as bytes: % 02[1]X\n", message, []byte(message))
	t.Logf("    original bits: %08b\n", []byte(message))

	// Re-write in 7 bit chunks to buf:
	var buf bytes.Buffer
	bw := NewWriter(&buf)
	for _, r := range message {
		if err := bw.Write(uint64(r), 1); err != nil { // nolint: errcheck
			t.Error(err)
		}
		if err := bw.Write(uint64(r)>>1, 2); err != nil { // nolint: errcheck
			t.Error(err)
		}
		if err := bw.Write(uint64(r)>>3, 3); err != nil { // nolint: errcheck
			t.Error(err)
		}
		if err := bw.Write(uint64(r)>>6, 2); err != nil { // nolint: errcheck
			t.Error(err)
		}
	}
	msg2 := "writebytes"
	if err := bw.WriteBytes([]byte(msg2)); err != nil {
		t.Error(err)
	}
	if err := bw.Close(); err != nil {
		log.Fatal(err)
	}
	t.Logf("Written bitstream: %08b\n", buf.Bytes())
	t.Logf("Written bytes: % 02X\n", buf.Bytes())

	// Read back in 7 bit chunks:
	br := NewReader(&buf)
	var result []byte
	for i := 0; i < len(message); i++ {
		v1, err := br.Read(3)
		if err != nil {
			t.Error(err)
		}
		v2, err := br.Read(1)
		if err != nil {
			t.Error(err)
		}
		v3, err := br.Read(1)
		if err != nil {
			t.Error(err)
		}
		v4, err := br.Read(3)
		if err != nil {
			t.Error(err)
		}
		v := (v4 << 5) | (v3 << 4) | (v2 << 3) | v1
		if v != 0 {
			result = append(result, byte(v))
		}
	}
	b, err := br.ReadBytes(len(msg2))
	if err != nil {
		t.Error(err)
	}
	if string(result) != message {
		t.Error("incorrect")
	}
	if string(b) != msg2 {
		t.Error("incorrect")
	}
	t.Logf("Read back as \"%s\"\n", result)
	// Output:
	// "This is a test." as bytes: 54 68 69 73 20 69 73 20 61 20 74 65 73 74 2E
	//     original bits: [01010100 01101000 01101001 01110011 00100000 01101001 01110011 00100000 01100001 00100000 01110100 01100101 01110011 01110100 00101110]
	// Written bitstream: [10101001 10100011 01001111 00110100 00011010 01111001 10100000 11000010 10000011 10100110 01011110 01111101 00010111 00000000]
	// Written bytes: A9 A3 4F 34 1A 79 A0 C2 83 A6 5E 7D 17 00
	// Read back as "This is a test."
}
