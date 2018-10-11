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
	"encoding/binary"

	"golang.org/x/crypto/blake2b"

	"golang.org/x/crypto/sha3"
)

const (
	epoolHashCount   = 10
	hashLengthUint16 = 64 / 2
	hashLengthUint64 = 64 / 8
)

type sum512 func([]byte) [64]byte

type entropyT struct {
	bitPool    uint64
	charPool   [64 * epoolHashCount]byte
	int16Pool  [hashLengthUint16 * epoolHashCount]uint16
	int64Pool  [hashLengthUint64 * epoolHashCount]uint64
	seed       [64]byte
	bitIndex   uint32
	charIndex  uint32
	int16Index uint32
	int64Index uint32
	sum512     sum512
	isTest     bool
}

/*
 * Increment the seed
 * (we treat it as an array of bytes/little-endian)
 */
func (entropy *entropyT) incrementSeed() {
	for i := 0; i < 64; i++ {
		entropy.seed[i]++
		if entropy.seed[i] > 0 {
			break
		}
	}
}

/*
 * Store random bits into the hash array.
 * Then increment the entropy->seed.
 *
 * - hash must be an array of n * SHA3_512_DIGEST_LENGTH bytes
 *   (i.e., n * 64 bytes)
 */
func (entropy *entropyT) refresh(n uint) []byte {
	hash := make([]byte, n*64)
	for i := uint(0); i < n; i++ {
		d := entropy.sum512(entropy.seed[:])
		copy(hash[i*64:], d[:])
		entropy.incrementSeed()
	}
	return hash
}

func (entropy *entropyT) charPoolRefresh() {
	charPool := entropy.refresh(epoolHashCount)
	copy(entropy.charPool[:], charPool)
	entropy.charIndex = 0
}

func (entropy *entropyT) int16PoolRefresh() {
	charPool := entropy.refresh(epoolHashCount)
	for i := 0; i < hashLengthUint16*epoolHashCount; i++ {
		entropy.int16Pool[i] = binary.LittleEndian.Uint16(charPool[i*2:])
	}
	entropy.int16Index = 0
}

func (entropy *entropyT) int64PoolRefresh() {
	charPool := entropy.refresh(epoolHashCount)
	for i := 0; i < hashLengthUint64*epoolHashCount; i++ {
		entropy.int64Pool[i] = binary.LittleEndian.Uint64(charPool[i*8:])
	}
	entropy.int64Index = 0
}

/*
 * Random 64bit integer
 */
func (entropy *entropyT) randomUint64() uint64 {
	if entropy == nil {
		panic("entropy must not be nil")
	}

	if entropy.int64Index >= hashLengthUint64*epoolHashCount {
		entropy.int64PoolRefresh()
	}
	if entropy.int64Index >= hashLengthUint64*epoolHashCount {
		panic("invalid int64 index")
	}
	entropy.int64Index++
	return entropy.int64Pool[entropy.int64Index-1]
}

/*
 * Random 16bit integer
 */
func (entropy *entropyT) randomUint16() uint16 {
	if entropy == nil {
		panic("entropy must not be nil")
	}

	if entropy.int16Index >= hashLengthUint16*epoolHashCount {
		entropy.int16PoolRefresh()
	}
	if entropy.int16Index >= hashLengthUint16*epoolHashCount {
		panic("invalid int64 index")
	}
	entropy.int16Index++
	return entropy.int16Pool[entropy.int16Index-1]
}

/*
 * Random byte
 */
func (entropy *entropyT) randomUint8() byte {
	if entropy.charIndex >= 64*epoolHashCount {
		entropy.charPoolRefresh()
	}
	entropy.charIndex++
	return entropy.charPool[entropy.charIndex-1]
}

/*
 * Use previous function to refresh bit pool
 */
func (entropy *entropyT) bitPoolRefresh() {
	entropy.bitPool = entropy.randomUint64()
	entropy.bitIndex = 0
}

/*
 * Get a random bit
 */
func (entropy *entropyT) randomBit() uint32 {
	if entropy == nil {
		panic("entropy must not be nil")
	}

	if entropy.bitIndex >= 64 {
		entropy.bitPoolRefresh()
	}
	bit := entropy.bitPool & 1
	entropy.bitPool >>= 1
	entropy.bitIndex++

	return uint32(bit)
}

/*
 * Return n random bits
 * - n must be no more than 32
 * - the n bits are low-order bits of the returned integer.
 */
func (entropy *entropyT) randomBits(n uint32) uint32 {
	if entropy == nil {
		panic("entropy must not be nil")
	}
	if n > 32 {
		panic("n must be <=32")
	}

	var retval uint32

	//slow, just for compatibility
	if entropy.isTest {
		for ; n > 0; n-- {
			retval <<= 1
			retval |= entropy.randomBit()
		}
		return retval
	}

	if entropy.bitIndex >= 64-n {
		entropy.bitPoolRefresh()
	}
	retval = uint32(entropy.bitPool & ((1 << n) - 1))
	entropy.bitPool >>= n
	entropy.bitIndex += n

	return retval
}

/*
 * Initialize: with the given seed
 * - seed must be an array of SHA3_512_DIGEST_LENGTH bytes
 */
func newEntropy(seed [64]uint8, isTest bool) *entropyT {
	entropy := &entropyT{
		seed:   seed,
		isTest: isTest,
		sum512: blake2b.Sum512,
	}
	if isTest {
		entropy.sum512 = sha3.Sum512
	}
	entropy.charPoolRefresh()
	entropy.int16PoolRefresh()
	entropy.int64PoolRefresh()
	entropy.bitPoolRefresh()
	return entropy
}
