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
	for i := 0; i < 1000; i++ {
		if _, err := rand.Read(text[:]); err != nil {
			t.Error(err)
		}
		if _, err := rand.Read(sd[:]); err != nil {
			t.Error(err)
		}
		for _, kind := range []Kind{B1, B2, B3, B4} {
			t.Log("kind", kind)
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

			if err = pub2.Verify(sig, text[:]); err != nil {
				t.Error(err)
			}
			if err = pub.Verify(sig2, text[:]); err != nil {
				t.Error(err)
			}
			param, err := GetParam(kind)
			if err != nil {
				t.Error(err)
			}
			if i == 0 {
				t.Log("sig size", param.SigSize(), "->", len(bsig))
				t.Log("sig size", param.SigSize()*8, "->", len(bsig)*8)
				t.Log("pk size", param.PKSize())
				t.Log("pk size", param.PKSize()*8)
			}
		}
	}
}
