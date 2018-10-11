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
	"bufio"
	"io"
)

// ==== Writing / Encoding ====

type writer interface {
	io.ByteWriter
	Flush() error
}

// Writer implements bit-wise writing to an io.Writer.
type Writer struct {
	w     writer
	bits  uint64
	nBits uint
}

// Write writes `width` bits of `c` in LSB order.
func (w *Writer) Write(c uint64, width uint) error {
	mask := (uint64(1) << width) - 1
	w.bits |= (c & mask) << w.nBits
	w.nBits += width
	for w.nBits >= 8 {
		if err := w.w.WriteByte(uint8(w.bits)); err != nil {
			return err
		}
		w.bits >>= 8
		w.nBits -= 8
	}
	return nil
}

//WriteBytes write byte slice
func (w *Writer) WriteBytes(bytes []byte) error {
	for i := 0; i < len(bytes); i++ {
		if err := w.Write(uint64(bytes[i]), 8); err != nil {
			return err
		}
	}
	return nil
}

// Close closes the writer, flushing any pending output.
// It does not close the underlying writer.
func (w *Writer) Close() error {
	// Write the final bits (zero padded).
	if w.nBits > 0 {
		if err := w.w.WriteByte(uint8(w.bits)); err != nil {
			return err
		}
	}
	return w.w.Flush()
}

// NewWriter returns a new bit Writer that writes completed bytes to `w`.
func NewWriter(w io.Writer) *Writer {
	var bw Writer
	if byteWriter, ok := w.(writer); ok {
		bw.w = byteWriter
	} else {
		bw.w = bufio.NewWriter(w)
	}
	return &bw
}

// ==== Reading / Decoding ====

// Reader implements bit-wise reading from an io.Reader.
type Reader struct {
	r     io.ByteReader
	bits  uint64
	nBits uint
}

// ReadLSB reads up to 16 bits from the underlying reader.
func (r *Reader) Read(width uint) (uint64, error) {
	for r.nBits < width {
		x, err := r.r.ReadByte()
		if err != nil {
			return 0, err
		}
		r.bits |= uint64(x) << r.nBits
		r.nBits += 8
	}
	bits := r.bits & (uint64(1)<<width - 1)
	r.bits >>= width
	r.nBits -= width
	return bits, nil
}

//ReadMSB read a uint32 in MSB order.
func (r *Reader) ReadMSB(width uint) (uint32, error) {
	for r.nBits < width {
		x, err := r.r.ReadByte()
		if err != nil {
			return 0, err
		}
		r.bits |= uint64(x) << (64 - 8 - r.nBits)
		r.nBits += 8
	}
	bits := uint32(r.bits >> (64 - width))
	r.bits <<= width
	r.nBits -= width
	return bits, nil
}

//ReadBytes read byte slice.
func (r *Reader) ReadBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	for i := 0; i < n; i++ {
		v, err := r.Read(8)
		if err != nil {
			return nil, err
		}
		b[i] = byte(v)
	}
	return b, nil
}

// Close closes the reader.
// It does not close the underlying reader.
func (r *Reader) Close() error {
	return nil
}

// NewReader returns a new bit Reader that reads bytes from `r`.
func NewReader(r io.Reader) *Reader {
	br := new(Reader)
	br.SetReader(r)
	return br
}

// SetReader set ior to reader of r.
func (r *Reader) SetReader(ior io.Reader) {
	if byteReader, ok := ior.(io.ByteReader); ok {
		r.r = byteReader
	} else {
		r.r = bufio.NewReader(ior)
	}
}
