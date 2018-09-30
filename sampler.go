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

type samplerT struct {
	entropy    *entropyT
	c          []byte /* the table we will use for Boolean sampling (from tables.h) */
	sigma      uint32 /* the standard deviation of the distribution */
	ell        uint32 /* rows in the table     */
	precision  uint32 /* precision used in computing the tables */
	ksigma     uint16 /* k_sigma = ceiling[ sqrt(2*ln 2) * sigma ]  */
	ksigmaBits uint16 /* number of significant bits in k_sigma */
}

func (sampler *samplerT) columns() int {
	return int(sampler.precision) / 8
}

/*
 * Initialize sampler:
 * - return true if success/false if error
 * - false means that the parameters sigma/ell/precisions are not supported
 */
func newSampler(sigma uint32, ell uint32, precision uint32, entropy *entropyT) *samplerT {
	sampler := &samplerT{
		entropy:    entropy,
		sigma:      sigma,
		ell:        ell,
		precision:  precision,
		c:          getTable(sigma, ell, precision),
		ksigma:     getKSigma(sigma, precision),
		ksigmaBits: getKSigmaBits(sigma, precision),
	}
	return sampler
}

/*
 * Sampling Bernoulli_c with c a constant in [0, 1]
 * - p = array of bytes (encoding c in big-endian format)
 * - p must have as many bytes as sampler->columns (= precision/8)
 */
func (sampler *samplerT) ber(p []byte) bool {
	if sampler == nil || p == nil {
		panic("sampler and p must not be nil")
	}

	for i := 0; i < sampler.columns(); i++ {
		uc := sampler.entropy.randomUint8()
		if uc < p[i] {
			return true
		}
		if uc > p[i] {
			return false
		}
	}
	return true // default value
}

/*
 * Sampling Bernoulli_E with E = exp(-x/(2*sigma*sigma)).
 * Algorithm 8 from DDLL
 */
func (sampler *samplerT) berExp(x uint32) bool {
	ri := sampler.ell - 1
	mask := uint32(1) << ri
	row := int(ri) * sampler.columns()
	for mask > 0 {
		if x&mask != 0 {
			bit := sampler.ber(sampler.c[row:])
			if !bit {
				return false
			}
		}
		mask >>= 1
		row -= sampler.columns()
	}

	return true
}

/*
 * Sampling Bernoulli_C with C = 1/cosh(x/(sigma*sigma))
 */
func (sampler *samplerT) berCosh(x int32) bool {
	// How do we know this does not overflow/underflow?
	if x < 0 {
		x = -x
	}
	x <<= 1

	for {
		bit := sampler.berExp(uint32(x))
		if bit {
			return true
		}

		bit = sampler.entropy.randomBit()
		if !bit {
			bit2 := sampler.berExp(uint32(x))
			if !bit2 {
				return false
			}
		}
	}
}

/*
 * Sample a non-negative integer according to the binary discrete
 * Gaussian distribution.
 *
 * Algorithm 10 in DDLL.
 */

const maxSampleCount = 16

func (sampler *samplerT) posBinary() uint32 {
restart:
	if sampler.entropy.randomBit() {
		return 0
	}

	for i := uint32(1); i <= maxSampleCount; i++ {
		u := sampler.entropy.randomBits(2*i - 1)
		if u == 0 {
			return i
		}
		if u != 1 {
			goto restart
		}
	}
	return 0 // default value. Extremely unlikely to ever be reached
}

/*
 * Sampling the Gaussian distribution exp(-x^2/(2*sigma*sigma))
 *
 * returns the sampled value.
 *
 * Combination of Algorithms 11 and 12 from DDLL.
 */
func (sampler *samplerT) gauss() int32 {
	var valpos int32
	var x, y uint32
	var u bool
	for {
		x = sampler.posBinary()
		for {
			y = sampler.entropy.randomBits(uint32(sampler.ksigmaBits))
			if y < uint32(sampler.ksigma) {
				break
			}
		}

		e := y * (y + 2*uint32(sampler.ksigma)*x)
		u = sampler.entropy.randomBit()
		// don't restart if both hold:
		// 1. (x, y) != (0, 0) or u = 1
		// 2. sampler_ber_exp(sampler, e) = 1
		if (x|y != 0 || u) && sampler.berExp(e) {
			break // lazy sample}
		}
	}
	valpos = int32(uint32(sampler.ksigma)*x + y)
	if !u {
		valpos = -valpos
	}
	return valpos
}
