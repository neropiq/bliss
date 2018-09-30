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
	"crypto/rand"
	"testing"
)

func TestSerializa(t *testing.T) {
	var text [1024]byte
	var sd [64]byte
	if _, err := rand.Read(text[:]); err != nil {
		t.Error(err)
	}
	if _, err := rand.Read(sd[:]); err != nil {
		t.Error(err)
	}
	for _, kind := range []Kind{B0, B1, B2, B3, B4} {
		pk := NewPrivateKey(kind, sd)
		pub := pk.PublicKey()
		sig := pk.Sign(text[:])

		bpub := pub.Bytes()
		bsig := sig.Bytes()
		pub2, err := NewPublicKey(bpub)
		if err != nil {
			t.Error(err)
		}
		sig2, err := NewSignature(bsig)
		if err != nil {
			t.Error(err)
		}
		if pub2.kind != kind {
			t.Error("invalid pub kind")
		}
		if sig2.kind != kind {
			t.Error("invalid sig kind")
		}

		for i := range pub.a {
			if pub.a[i] != pub2.a[i] {
				t.Error("incorrect pub a")
			}
		}
		for i := range sig.z1 {
			if sig.z1[i] != sig2.z1[i] {
				t.Error("incorrect sig z1")
			}
		}
		for i := range sig.z2 {
			if sig.z2[i] != sig2.z2[i] {
				t.Error("incorrect sig z2")
			}
		}
		for i := range sig.c {
			if sig.c[i] != sig2.c[i] {
				t.Error("incorrect sig c")
			}
		}

		if err := pub2.Verify(sig, text[:]); err != nil {
			t.Error(err)
		}
		if err := pub.Verify(sig2, text[:]); err != nil {
			t.Error(err)
		}
		p, err := GetParam(kind)
		if err != nil {
			t.Error(err)
		}
		rs := make([]byte, p.n)
		mask1 := ^(^0 << (p.bBits - 8 - 1))
		mask2 := ^(^0 << (p.z2bits()))
		for i := range sig.z1 {
			z1 := sig.z1[i]
			z2 := sig.z2[i]
			if z1 < 0 {
				z1 = -z1
			}
			z1 = (z1 >> 8) & int32(mask1)
			z2 &= int32(mask2)
			rs[i] = byte((z1 << 4) | z2)
		}
		cmp, err := compress(rs)
		if err != nil {
			t.Error(err)
		}
		t.Log(len(cmp), len(rs))
	}
	t.Fatal()
}
