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
	"crypto/rand"
	"errors"
	"fmt"
	"log"

	"golang.org/x/crypto/blake2b"

	"golang.org/x/crypto/sha3"
)

//SignatureT is a signature of BLISS-B.
type SignatureT struct {
	kind Kind     /* the kind of bliss       */
	z1   []int32  /* bliss signature polynomial                */
	z2   []int32  /* bliss signature polynomial                */
	c    []uint32 /* indices of sparse vector of size kappa    */
}

const verboseRestart = false

/* iam: bliss-06-13-2013 */
func mul2d(input []int32, n int, d uint32) []int32 {
	if 0 >= d || d >= 31 {
		panic("invalid d")
	}

	output := make([]int32, n)
	for i := 0; i < n; i++ {
		output[i] = input[i] << d
	}
	return output
}

func checkarg(v []int32, q int32) bool {
	for i := range v {
		if v[i] < 0 {
			return false
		}
		if v[i] >= q {
			return false
		}
	}

	return true
}

/* iam: bliss-06-13-2013
 *
 *   on page 21 of DDLL: every x between [-q, q) and any positive integer d, x can be uniquely written
 *   as  x = [x]_d * 2^d  + r where r is in [-2^(d -1), 2^(d -1)).
 *
 *   this is computing: x -. [x]_d
 *
 */
func dropBits(input []int32, n int, d uint32) []int32 {
	if 0 >= d || d >= 31 {
		panic("invalid d")
	}

	delta := int32(1) << d
	halfdelta := delta >> 1
	output := make([]int32, n)
	for i := 0; i < n; i++ {
		output[i] = (input[i] + halfdelta) / delta
	}
	return output
}

/*
 * GreedySC (derived from blzzd version)
 *
 * should be static once we choose one and use it.
 *
 * Input:  s1, s2, are the polynomial components of the secret key.
 *         c_indices correspond to the sparse polynomial
 *
 * Output: v1 and v2 are output polynomials of size n.
 *
 */
func greedySC(s1 []int32, s2 []int32, n int, cIndices []uint32, kappa uint32) ([]int32, []int32) {
	v1 := make([]int32, n)
	v2 := make([]int32, n)

	for k := uint32(0); k < kappa; k++ {
		index := int(cIndices[k])
		var sign int32
		/* \xi_i = sign(<v, si>) */
		for i := 0; i < n-index; i++ {
			sign += s1[i]*v1[index+i] + s2[i]*v2[index+i]
		}
		for i := n - index; i < n; i++ {
			sign -= s1[i]*v1[index+i-n] + s2[i]*v2[index+i-n]
		}
		/* v = v - \xi_i . si */
		if sign > 0 {
			for i := 0; i < n-index; i++ {
				v1[index+i] -= s1[i]
				v2[index+i] -= s2[i]
			}
			for i := n - index; i < n; i++ {
				v1[index+i-n] += s1[i]
				v2[index+i-n] += s2[i]
			}
		} else {
			for i := 0; i < n-index; i++ {
				v1[index+i] += s1[i]
				v2[index+i] += s2[i]
			}
			for i := n - index; i < n; i++ {
				v1[index+i-n] -= s1[i]
				v2[index+i-n] -= s2[i]
			}
		}
	}
	return v1, v2
}

func generateC(kappa uint32, nVector []int32, n int, hash []byte) []uint32 {
	indices := make([]uint32, kappa)

	if (n != 256 && n != 512) || len(hash) != 64+2*n {
		panic("invalid params")
	}
	/*
	 * append the n_vector to the hash array
	 */
	j := 64
	for i := 0; i < n; i++ {
		// n_vector[i] is between 0 and modP (less than 2^16)
		x := uint32(nVector[i])
		hash[j] = byte(x & 255)
		hash[j+1] = byte((x >> 8) & 0xff)
		j += 2
	}

	/* We bail out after 256 iterations in case something goes wrong. */
	for tries := 0; tries < 256; tries++ {
		/*
		 * BD: just to be safe, we shouldn't overwrite the last element of hash
		 * (so that n_vector[n-1] is taken into account).
		 */
		hash[len(hash)-1]++
		whash := sha3.Sum512(hash)

		var array [512]byte
		if n == 256 {
			/* Bliss_b 0: we need kappa indices of 8 bits */
			var i uint32
			for j := 0; j < 64; j++ {
				index := whash[j]
				if array[index] == 0 {
					indices[i] = uint32(index)
					array[index] = 1
					i++
					if i >= kappa {
						return indices
					}
				}
			}
		} else {
			var extraBits byte // Prevent a GCC warning

			/* We need kappa indices of 9 bits */
			var i uint32
			j = 0
			for j < 64 {
				if (j & 7) == 0 {
					/* start of a block of 8 bytes */
					extraBits = whash[j]
					j++
				}
				index := (uint32(whash[j]) << 1) | uint32(extraBits&1)
				extraBits >>= 1
				j++

				if array[index] == 0 {
					indices[i] = index
					array[index] = 1
					i++
					if i >= kappa {
						return indices
					}
				}
			}
		}
	}
	return indices
}

//Sign signs msg by pk.
func (pk *PrivateKeyT) Sign(msg []byte) *SignatureT {
	var seed [64]byte
	if _, err := rand.Read(seed[:]); err != nil {
		panic(err)
	}
	return pk.sign(msg, newEntropy(seed, blake2b.Sum512))
}

func (pk *PrivateKeyT) sign(msg []byte, entropy *entropyT) *SignatureT {
	p := newBlissParams(pk.kind)
	n := p.n

	//opaque, but clearly a pointer type.
	state := newNtt(pk.kind)

	/* initialize our sampler */
	sampler := newSampler(p.sigma, p.ell, p.precision, entropy)

	/* make working space */
	hashSZ := 64 + 2*n
	hash := make([]byte, hashSZ)

	/* 0: compute the hash of the msg */

	/* hash the message into the first SHA3_512_DIGEST_LENGTH bytes of the hash */
	h := sha3.Sum512(msg)
	copy(hash, h[:])
	y1 := make([]int32, n)
	y2 := make([]int32, n)
	z1 := make([]int32, n)
	z2 := make([]int32, n)

restart:

	for i := 0; i < n; i++ {
		y1[i] = sampler.gauss()
		y2[i] = sampler.gauss()
	}

	/* 2: compute v = ((2 * xi * a * y1) + y2) mod 2q */
	v := state.multiply(y1, pk.a)

	for i := 0; i < n; i++ {
		// this is v[i] = (2 * v[i] * xi + y2[i]) % q2
		v[i] = smodq(2*v[i]*p.oneQ2+y2[i], p.q2)
	}

	/* 2b: drop bits modP */

	if !checkarg(v, p.q2) {
		panic("invalid args")
	}
	dv := dropBits(v, n, p.d)
	for i := 0; i < n; i++ {
		dv[i] = smodq(dv[i], p.modP)
	}

	indices := generateC(p.kappa, dv, n, hash[:])

	/* 4: (v1, v2) = greedySC(c) */

	v1, v2 := greedySC(pk.s1, pk.s2, n, indices, p.kappa)

	/* 4a: continue with probability 1/(M exp(-|v|^2/2sigma^2) otherwise restart */
	// NOTE: we can do the ber_exp earlier since it does not depend on z
	normV := uint32(vectorNorm2(v1) + vectorNorm2(v2))

	if p.bigM <= normV {
		panic(fmt.Sprintf("M = %v norm = %v\n", p.bigM, normV))
	}

	if !sampler.berExp(p.bigM - normV) {
		if verboseRestart {
			log.Println("-. sampler_ber_exp false")
		}
		goto restart
	}

	/* 5: choose a random bit b */
	b := entropy.randomBit()

	/* 6: (z1, z2) = (y1, y2) + (-1)^b * (v1, v2) */

	if b {
		for i := 0; i < n; i++ {
			z1[i] = y1[i] - v1[i]
			z2[i] = y2[i] - v2[i]
		}
	} else {
		for i := 0; i < n; i++ {
			z1[i] = y1[i] + v1[i]
			z2[i] = y2[i] + v2[i]
		}
	}

	/* 6a: continue with probability 1/cosh(<z, v>/sigma^2)) otherwise restart */
	prodZV := vectorscalarProduct(z1, v1) + vectorscalarProduct(z2, v2)
	if !sampler.berCosh(prodZV) {
		if verboseRestart {
			log.Println("-. sampler_ber_cosh false")
		}
		goto restart
	}

	/* 7: z2 = (drop_bits(v) - drop_bits(v - z2)) mod p  */
	for i := 0; i < n; i++ {
		y1[i] = smodq(v[i]-z2[i], p.q2)
	}
	if !checkarg(v, p.q2) {
		panic("invalid v")
	}
	v = dropBits(v, n, p.d) // drop_bits(v)
	if !checkarg(y1, p.q2) {
		panic("invalid y1")
	}
	y1 = dropBits(y1, n, p.d) // drop_bits(v - z2)
	for i := 0; i < n; i++ {
		z2[i] = v[i] - y1[i]
		if z2[i] < -p.modP/2 {
			z2[i] += p.modP
		} else if z2[i] > p.modP/2 {
			z2[i] -= p.modP
		}
		if -p.modP/2 > z2[i] || z2[i] >= p.modP/2 {
			panic("invalid z2")
		}
	}

	/* 8: Also need to check norms akin to what happens in the entry to verify for BLISS-0, BLISS-3 and BLISS-4 */
	if uint32(vectorMaxNorm(z1)) > p.bInf {
		if verboseRestart {
			log.Println("-. norm z1 too high")
		}
		goto restart
	}
	y2 = mul2d(z2, n, p.d)
	if uint32(vectorMaxNorm(y2)) > p.bInf {
		if verboseRestart {
			log.Println("-. norm z2*2^d too high")
		}
		goto restart
	}
	if uint32(vectorNorm2(z1)+vectorNorm2(y2)) > p.bL2 {
		if verboseRestart {
			log.Println("-. euclidean norm too high")
		}
		goto restart
	}

	/* return (z1, z2, c) */

	sig := &SignatureT{
		kind: p.kind,
		z1:   z1,
		z2:   z2,
		c:    indices,
	}

	/* need to free some stuff */

	secureFreePolynomial(&v)
	secureFree(&dv)
	secureFree(&y1)
	secureFree(&y2)
	secureFree(&v1)
	secureFree(&v2)

	return sig
}

var errBadData = errors.New("bad data")
var errVerification = errors.New("failed to verify")

//Verify verifies signature with pub.
func (pub *PublicKeyT) Verify(signature *SignatureT, msg []byte) error {
	if pub.kind != signature.kind {
		return errors.New("different kind")
	}
	p := newBlissParams(pub.kind)

	n := p.n

	z1 := signature.z1      /* length n */
	z2 := signature.z2      /* length n */
	cIndices := signature.c /* length kappa */

	//opaque, but clearly a pointer type.
	state := newNtt(pub.kind)

	/* first check the norms */

	if uint32(vectorMaxNorm(z1)) > p.bInf {
		return errBadData
	}

	/* multiply z2 by 2^d */
	tz2 := mul2d(z2, n, p.d)

	if uint32(vectorMaxNorm(tz2)) > p.bInf {
		return errBadData
	}

	if uint32(vectorNorm2(z1)+vectorNorm2(tz2)) > p.bL2 {
		return errBadData
	}

	/* make working space */

	hashSZ := 64 + 2*n
	hash := make([]byte, hashSZ)

	/* start the real work */

	/* hash the message into the first SHA3_512_DIGEST_LENGTH bytes of the hash */
	h := sha3.Sum512(msg)
	copy(hash, h[:])

	/* v = a * z1 */
	v := state.multiply(z1, pub.a)

	/* v = (1/(q + 2)) * a * z1 mod 2q */
	for i := 0; i < n; i++ {
		if 0 > v[i] || v[i] >= p.q {
			panic("invalid v")
		}
		v[i] = smodq(2*v[i]*p.oneQ2, p.q2)
	}

	/* v += (q/q+2) * c */
	for i := uint32(0); i < p.kappa; i++ {
		idx := cIndices[i]
		v[idx] = smodq(v[idx]+(p.q*p.oneQ2), p.q2) // TODO: store that in parameters?
	}

	if !checkarg(v, p.q2) {
		panic("invalid arg")
	}
	v = dropBits(v, n, p.d)

	/*  v += z_2  mod p. */
	for i := 0; i < n; i++ {
		v[i] = smodq(v[i]+z2[i], p.modP)
	}

	indices := generateC(p.kappa, v, p.n, hash[:])

	for i := uint32(0); i < p.kappa; i++ {
		if indices[i] != cIndices[i] {
			return errVerification
		}
	}
	return nil
}
