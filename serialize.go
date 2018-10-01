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

//Bytes serialize Publickey.
func (p *PublicKeyT) Bytes() []byte {
	var buf bytes.Buffer
	w := bit.NewWriter(&buf)

	if err := w.Write(uint64(p.kind), 3); err != nil {
		panic(err)
	}
	stat := newNtt(p.kind)
	param, err := GetParam(p.kind)
	if err != nil {
		panic(err)
	}
	a := stat.inverse(p.a)
	for _, t := range a {
		if err := w.Write(uint64(t), param.qBits); err != nil {
			panic(err)
		}
	}
	if err := w.Close(); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

//NewPublicKey creates an Publickey from serialized bytes.
func NewPublicKey(b []byte) (*PublicKeyT, error) {
	//check before setbytes to ensure that the data is not too big
	if len(b) > blissBParams[4].PKSize() {
		return nil, errors.New("invalid length of data")
	}

	buf := bytes.NewBuffer(b)
	r := bit.NewReader(buf)
	kind, err := r.Read(3)
	if err != nil {
		return nil, err
	}
	param, err := GetParam(Kind(kind))
	if err != nil {
		return nil, err
	}
	p := &PublicKeyT{
		kind: param.kind,
		a:    make([]int32, param.n),
	}
	if len(b) != param.PKSize() {
		return nil, errors.New("invalid length of bytes for PK")
	}
	for i := range p.a {
		a, err := r.Read(param.qBits)
		if err != nil {
			return nil, err
		}
		p.a[i] = int32(a)
	}
	stat := newNtt(p.kind)
	p.a = stat.forward(p.a)
	return p, p.check(param)
}

//Bytes serialize SigningKey.
func (s *SignatureT) Bytes() []byte {
	param, err := GetParam(s.kind)
	if err != nil {
		panic(err)
	}
	var buf bytes.Buffer
	w := bit.NewWriter(&buf)

	//kind
	if err = w.Write(uint64(s.kind), 3); err != nil {
		panic(err)
	}

	//compressed z1 and z2
	rs := make([]byte, param.n)
	mask1 := (1 << (param.bBits - 8 - 1)) - 1
	for i := range s.z1 {
		z1 := s.z1[i]
		z2 := s.z2[i]
		if z1 < 0 {
			z1 = -z1
		}
		if z2 < 0 {
			z2 = -z2
			z2 |= 1 << 3
		}
		z1 = (z1 >> 8) & int32(mask1)
		rs[i] = byte((z1 << 4) | z2)
	}
	// cmp, err := compress(rs)
	cmp, bitlen, err := encodeHuff(param.kind, rs)
	if err != nil {
		panic(err)
	}
	if err := w.Write(uint64(bitlen), param.nBits+3); err != nil {
		panic(err)
	}
	if err := w.WriteBytes(cmp); err != nil {
		panic(err)
	}

	for _, t := range s.z1 {
		if t < 0 {
			t = -t
			t = t & 0xff
			t |= int32(1) << 8
		} else {
			t = t & 0xff
		}
		if err := w.Write(uint64(t), 9); err != nil {
			panic(err)
		}
	}

	for _, c := range s.c {
		if err := w.Write(uint64(c), param.nBits); err != nil {
			panic(err)
		}
	}

	if err := w.Close(); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

//NewSignature creates an SiningKey from serialized bytes.
func NewSignature(b []byte) (*SignatureT, error) {
	//check before setbytes to ensure that the data is not too big
	// if len(b) > blissBParams[4].SigSize() {
	// 	return nil, errors.New("invalid length of data")
	// }
	r := bit.NewReader(bytes.NewBuffer(b))

	kind, err := r.Read(3)
	if err != nil {
		return nil, err
	}
	param, err := GetParam(Kind(kind))
	if err != nil {
		return nil, err
	}
	// if len(b) > param.SigSize() {
	// 	return nil, errors.New("invalid length of bytes for signature")
	// }
	s := &SignatureT{
		kind: param.kind,
		z1:   make([]int32, param.n),
		z2:   make([]int32, param.n),
		c:    make([]uint32, param.kappa),
	}
	bitlen, err := r.Read(param.nBits + 3)
	if err != nil {
		return nil, err
	}

	bytelen := bitlen / 8
	if bitlen%8 != 0 {
		bytelen++
	}
	cmp, err := r.ReadBytes(int(bytelen))
	if err != nil {
		return nil, err
	}

	// unc, err := extract(cmp)
	unc, err := decodeHuff(param.kind, cmp, int(bitlen))
	if err != nil {
		return nil, err
	}
	if len(unc) != param.n {
		return nil, errors.New("invalid lengh of compressed data")
	}
	clearTop32 := (int32(1) << 3) - 1
	for i, u := range unc {
		s.z1[i] = (int32(u&0xf0) >> 4) << 8
		z2 := int32(u & 0x0f)
		if z2&(1<<3) != 0 {
			s.z2[i] = -(z2 & clearTop32)
		} else {
			s.z2[i] = z2 & clearTop32
		}
	}

	clearTop := uint64(^(^0 << 8))
	for i := range s.z1 {
		z1, err := r.Read(9)
		if err != nil {
			return nil, err
		}
		s.z1[i] |= int32(z1 & clearTop)
		if z1&(1<<8) != 0 {
			s.z1[i] = -s.z1[i]
		}
	}

	clearTop = ^(^uint64(0) << param.nBits)
	for i := range s.c {
		c, err := r.Read(param.nBits)
		if err != nil {
			return nil, err
		}
		s.c[i] = uint32(c & clearTop)
	}
	return s, s.check(param)
}

func (p *PublicKeyT) check(param *ParamT) error {
	if len(p.a) != param.n {
		return errors.New("invalid length of a")
	}
	for _, a := range p.a {
		if a < 0 || a >= param.q {
			return errors.New("invalid a")
		}
	}
	return nil
}

func (s *SignatureT) check(p *ParamT) error {
	if len(s.z1) != p.n {
		return errors.New("invalid length of z1")
	}
	if len(s.z2) != p.n {
		return errors.New("invalid length of z2")
	}
	if len(s.c) != int(p.kappa) {
		return errors.New("invalid length of c")
	}
	for _, z1 := range s.z1 {
		if z1 <= -int32(p.bInf) || z1 >= int32(p.bInf) {
			return errors.New("invalid z1")
		}
	}
	z2max := 1 << p.z2bits()
	for _, z2 := range s.z2 {
		if z2 <= -int32(z2max) || z2 >= int32(z2max) {
			return errors.New("invalid z2")
		}
	}
	for _, c := range s.c {
		if c >= uint32(p.n) {
			return errors.New("invalid c")
		}
	}
	return nil
}

// func compress(r []byte) ([]byte, error) {
// 	buf := new(bytes.Buffer)
// 	err2 := func() error {
// 		zw, err := flate.NewWriter(buf, flate.HuffmanOnly)
// 		if err != nil {
// 			return err
// 		}
// 		defer zw.Close()
// 		n, err := zw.Write(r)
// 		if err != nil {
// 			return err
// 		}
// 		if n != len(r) {
// 			return errors.New("coulnd compress")
// 		}
// 		return nil
// 	}()
// 	if err2 != nil {
// 		return nil, err2
// 	}
// 	return buf.Bytes(), nil
// }

// func extract(zr []byte) ([]byte, error) {
// 	buf := bytes.NewBuffer(zr)
// 	r := flate.NewReader(buf)
// 	defer r.Close()
// 	return ioutil.ReadAll(r)
// }
