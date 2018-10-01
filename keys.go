// Copyright (c) 2017 Aidos Developer

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

//This code is a rewrite of https://github.com/SRI-CSL/Bliss, whici is covered by MIT License.
// Copyright (c) 2017 Tancrède Lepoint

package bliss

import (
	"golang.org/x/crypto/blake2b"
)

//PrivateKeyT is a bliss-b private key
type PrivateKeyT struct {
	kind Kind    /* the kind of bliss       */
	s1   []int32 /* sparse polynomial s1    */
	s2   []int32 /* sparse polynomial s2    */
	a    []int32 /* NTT of s1/s2            */
}

//PublicKeyT is a bliss-b public key
type PublicKeyT struct {
	kind Kind    /* the kind of bliss       */
	a    []int32 /* NTT of s1/s2           */
}

/*
   Constructs a random polyomial
   - v: where the random polynomial is stored
   - n: the length of the polynomial
   - nz1: the number of coefficients that are +-1
   - nz2: the number of coefficients that are +-2
   - entropy: an initialized source of randomness
*/
func uniformPoly(n int, nz1, nz2 uint32, entropy *entropyT) []int32 {
	v := make([]int32, n)
	for i := int32(0); i < int32(nz1); {
		x := int32(entropy.randomUint16())
		j := (x >> 1) % int32(n)             // nb: uniform because n is a power of 2
		mask := -(1 ^ (v[j] & 1))            // mask = 1...1 if v[j] == 0 else 0
		i += mask & 1                        // add 1 only if v[j] == 0
		v[j] += (-1 + ((x & 1) << 1)) & mask // v[j] = -1 if x&1 == 0 else 1
	}

	for i := int32(0); i < int32(nz2); {
		x := int32(entropy.randomUint16())
		j := (x >> 1) % int32(n)                        // nb: uniform because n is a power of 2
		mask := -(1 ^ ((v[j] & 1) | ((v[j] & 2) >> 1))) // mask = 1...1 if v[j] == 0 or v[j] == 1 else 0
		i += mask & 1                                   // add 1 only if v[j] == 0 or v[j] == 1
		v[j] += (-2 + ((x & 1) << 2)) & mask            // v[j] = -2 if x&1 == 0 else 2
	}
	return v
}

/**
  Bliss-b public and sign key generation
         sign key is    f, g small and f invertible
         public key is  a_q = -(2g-1)/f mod q = (2g'+1)/f
*/

//NewPrivateKey return a private key for BLISS_B.
func NewPrivateKey(kind Kind, seed [64]byte) *PrivateKeyT {
	ent := newEntropy(seed, blake2b.Sum512)
	return newPrivateKey(kind, ent)
}

func newPrivateKey(kind Kind, entropy *entropyT) *PrivateKeyT {
	p, err := GetParam(kind)
	if err != nil {
		panic(err)
	}
	/* we calloc so we do not have to zero them out later */
	pk := &PrivateKeyT{
		kind: kind,
	}
	//opaque, but clearly a pointer type.
	state := newNtt(kind)
	var u []int32

	/* randomize g */
	pk.s2 = uniformPoly(p.n, p.nz1, p.nz2, entropy)

	/* g = 2g - 1   N.B the Bliss-B paper uses 2g + 1 */
	for i := 0; i < p.n; i++ {
		pk.s2[i] *= 2
	}
	pk.s2[0]--

	//N.B. ntt_t t
	t := state.forward(pk.s2)

	/* find an invertible f  */
	for j := 0; j < 4; j++ {

		/* randomize f  */
		pk.s1 = uniformPoly(p.n, p.nz1, p.nz2, entropy)

		/* Try again if f is not invertible. */
		u, err = state.invertPolynomial(pk.s1)
		if err != nil {
			continue
		}

		/* Success: u = ntt of f^-1. Compute a = (2g - 1)/f. */
		pk.a = state.product(t, u)
		pk.a = state.inverse(pk.a)

		// a = -1 * a
		pk.a = state.negate(pk.a)

		/* currently storing the pk.a in ntt form */
		pk.a = state.forward(pk.a)

		secureFreeNTT(&t)
		secureFree(&u)

		return pk
	}
	panic("should not happen")
}

//PublicKey extracs a public key from pk.
func (pk *PrivateKeyT) PublicKey() *PublicKeyT {
	if pk == nil {
		panic("private key must not be nil")
	}

	pub := &PublicKeyT{
		kind: pk.kind,
		a:    make([]int32, len(pk.a)),
	}
	copy(pub.a, pk.a)

	return pub
}
