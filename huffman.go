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

package bliss

import (
	"bytes"
	"errors"

	"github.com/AidosKuneen/bliss/bit"
)

func encodeHuff(kind Kind, in []byte) ([]byte, int, error) {
	param, err := GetParam(kind)
	if err != nil {
		return nil, 0, err
	}
	z2max := param.bInf / (1 << param.d)
	row := z2max*2 + 1
	encp := huffEncs[kind]
	var buf bytes.Buffer
	w := bit.NewWriter(&buf)
	bitlen := 0
	for _, inn := range in {
		z1 := (int(inn) & 0xf0) >> 4
		z2 := int(inn) & 0x0f
		if z2&0x08 != 0 {
			z2 &= 0x07
			z2 = -z2
		}
		index := z1*int(row) + z2 + int(z2max)
		if err := w.Write(uint64(encp[index][0]), uint(encp[index][1])); err != nil {
			return nil, 0, err
		}
		bitlen += encp[index][1]
	}
	if err := w.Close(); err != nil {
		return nil, 0, err
	}
	bs := buf.Bytes()
	for i := 0; i < len(bs)/2; i++ {
		bs[i], bs[len(bs)-1-i] = bs[len(bs)-1-i], bs[i]
	}
	return bs, bitlen, nil
}

func decodeHuff(kind Kind, in []byte, bitlen int) ([]byte, error) {
	param, err := GetParam(kind)
	if err != nil {
		return nil, err
	}
	buf := make([]byte, 0, param.n)
	r := bit.NewReader(bytes.NewBuffer(in))
	decp := huffDecs[kind]
	z2max := param.bInf / (1 << param.d)
	row := z2max*2 + 1

	_, err = r.ReadMSB(uint(len(in)*8 - bitlen))
	if err != nil {
		return nil, err
	}
	state := 0
	i := len(in)*8 - bitlen
	for ; i < len(in)*8 && len(buf) < param.n; i++ {
		d, err := r.ReadMSB(1)
		if err != nil {
			return nil, err
		}
		state = decp[state][d]
		if v := decp[state][2]; v != -1 {
			z1 := v / int(row)
			z2 := v%int(row) - int(z2max)
			if z2 < 0 {
				z2 = (-z2) | 0x08
			}
			b := byte(((z1 & 0x0f) << 4) | (z2 & 0x0f))
			buf = append(buf, b)
			state = 0
		}
	}
	if len(in)*8-i > 8 || state != 0 || len(buf) != param.n {
		return nil, errors.New("compressed data is curuppted")
	}
	for i := 0; i < len(buf)/2; i++ {
		buf[i], buf[len(buf)-1-i] = buf[len(buf)-1-i], buf[i]
	}
	return buf, nil
}
