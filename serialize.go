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
	"compress/flate"
	"errors"
	"io"
	"io/ioutil"
	"log"
	"math/big"
)

//Bytes serialize Publickey.
func (p *PublicKeyT) Bytes() []byte {
	var r big.Int
	stat := newNtt(p.kind)
	param, err := GetParam(p.kind)
	if err != nil {
		panic(err)
	}
	a := stat.inverse(p.a)
	for i := range a {
		r.Lsh(&r, param.qBits)
		t := a[param.n-1-i]
		tt := big.NewInt(int64(t))
		r.Or(&r, tt)
	}
	r.Lsh(&r, 3)
	tt := big.NewInt(int64(p.kind))
	r.Or(&r, tt)
	b := r.Bytes()
	bb := make([]byte, param.PKSize())
	log.Println(param.PKSize(), len(b))
	copy(bb[param.PKSize()-len(b):], b)
	return bb
}

//NewPublicKey creates an Publickey from serialized bytes.
func NewPublicKey(b []byte) (*PublicKeyT, error) {
	var r big.Int
	r.SetBytes(b)
	var v big.Int
	mask := ^(^0 << uint(3))
	maskQ := big.NewInt(int64(mask))
	v.And(&r, maskQ)
	kind := Kind(v.Uint64())
	r.Rsh(&r, 3)
	param, err := GetParam(kind)
	if err != nil {
		return nil, err
	}
	p := &PublicKeyT{
		kind: kind,
		a:    make([]int32, param.n),
	}
	if len(b) != param.PKSize() {
		return nil, errors.New("invalid length of bytes for PK")
	}
	mask = ^(^0 << param.qBits)
	maskQ = big.NewInt(int64(mask))
	for i := range p.a {
		v.And(&r, maskQ)
		p.a[i] = int32(v.Uint64())
		r.Rsh(&r, param.qBits)
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
	var r big.Int
	for i := range s.c {
		r.Lsh(&r, param.nBits)
		t := s.c[int(param.kappa)-1-i]
		tt := big.NewInt(int64(t))
		r.Or(&r, tt)
	}
	for i := range s.z2 {
		r.Lsh(&r, param.z2bits())
		t := s.z2[param.n-1-i]
		if t < 0 {
			t = -t
			t |= 1 << (param.z2bits() - 1)
		}
		tt := big.NewInt(int64(t))
		r.Or(&r, tt)
	}
	for i := range s.z1 {
		r.Lsh(&r, param.bBits)
		t := s.z1[param.n-1-i]
		if t < 0 {
			t = -t
			t |= int32(1) << (param.bBits - 1)
		}
		tt := big.NewInt(int64(t))
		r.Or(&r, tt)
	}
	r.Lsh(&r, 3)
	tt := big.NewInt(int64(s.kind))
	r.Or(&r, tt)
	b := r.Bytes()
	bb := make([]byte, param.SigSize())
	log.Println(param.SigSize(), len(b))
	copy(bb[param.SigSize()-len(b):], b)
	return bb
}

//NewSignature creates an SiningKey from serialized bytes.
func NewSignature(b []byte) (*SignatureT, error) {
	var r big.Int
	r.SetBytes(b)
	var v big.Int
	mask := ^(^0 << uint(3))
	maskQ := big.NewInt(int64(mask))
	v.And(&r, maskQ)
	kind := Kind(v.Uint64())
	r.Rsh(&r, 3)
	param, err := GetParam(kind)
	if err != nil {
		return nil, err
	}
	if len(b) != param.SigSize() {
		return nil, errors.New("invalid length of bytes for SK")
	}
	s := &SignatureT{
		kind: kind,
		z1:   make([]int32, param.n),
		z2:   make([]int32, param.n),
		c:    make([]uint32, param.kappa),
	}
	mask = ^(^0 << param.bBits)
	maskQ = big.NewInt(int64(mask))
	clearTop := ^(^uint64(0) << (param.bBits - 1))
	for i := range s.z1 {
		v.And(&r, maskQ)
		z1 := v.Uint64()
		s.z1[i] = int32(z1 & clearTop)
		if z1&(1<<(param.bBits-1)) != 0 {
			s.z1[i] = -s.z1[i]
		}
		r.Rsh(&r, param.bBits)
	}
	mask = ^(^0 << param.z2bits())
	maskQ = big.NewInt(int64(mask))
	clearTop = ^(^uint64(0) << (param.z2bits() - 1))
	for i := range s.z2 {
		v.And(&r, maskQ)
		z2 := v.Uint64()
		s.z2[i] = int32(z2 & clearTop)
		if z2&(1<<(param.z2bits()-1)) != 0 {
			s.z2[i] = -s.z2[i]
		}
		r.Rsh(&r, param.z2bits())
	}
	mask = ^(^0 << param.nBits)
	maskQ = big.NewInt(int64(mask))
	clearTop = ^(^uint64(0) << param.nBits)
	for i := range s.c {
		var v big.Int
		v.And(&r, maskQ)
		c := v.Uint64()
		s.c[i] = uint32(c & clearTop)
		r.Rsh(&r, param.nBits)
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
		if c < 0 || c >= uint32(p.n) {
			return errors.New("invalid c")
		}
	}
	return nil
}

func compress(r []byte) ([]byte, error) {
	buf := new(bytes.Buffer)
	zw, err := flate.NewWriter(buf, flate.BestSpeed)
	if err != nil {
		return nil, err
	}
	defer zw.Close()
	_, err = zw.Write(r)
	return buf.Bytes(), err
}

func extract(zr io.Reader) ([]byte, error) {
	r := flate.NewReader(zr)
	defer r.Close()
	return ioutil.ReadAll(r)
}
