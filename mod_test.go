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
	"encoding/binary"
	"math"
	"testing"
)

func average(t []float64) float64 {
	acc := 0.0
	for _, tt := range t {
		acc += tt / float64(len(t))
	}
	return acc
}

/*
 * https://blogs.msdn.microsoft.com/devdev/2005/12/12/integer-division-by-constants/
 *
 * To avoid division instructions, compilers use the equalities:
 *    x%Q = x - (x/Q) * Q
 *    x/Q = (x * K) >> k
 * for a constant K that's ceiling(2^k/Q). Clang/gcc use
 * k=45 and K=2863078533.
 *
 * We can pick other values for k, since x is between 0 and
 * (Q-1)^2. The following values work.
 *
 *       k |     K
 *   ----------------------
 *      41 |  178942409
 *      42 |  357884817
 *      43 |  715769634
 *      44 | 1431539267
 *      45 | 2863078533
 *  for k = 41 & Q = 7681
 *  K = 286293876
 *  for k = 41 & 2Q 15362 (Q = 7681)
 *  K = 143146938
 *  for k = 41 & Q = 12289
 *  K = 178942409
 *  for k = 41 & 2Q = 24578 (Q = 12289)
 *  K = 89471205
 *
 *
 * also need for mod_p  if we do it this way.
 *
 * another way would be to make K and k part of the params struct and
 * pass them is as arguments to the function:
 *
 * uint32_t divq(int32_t x, int32_t q, uint32_t k, uint32_t K) {
 *    return (((uint64_t) x) * K) >> k;
 * }
 *
 */
func divq(x, q int32) int32 {
	switch q {
	case 12289:
		return int32((uint64(x) * 178942409) >> 41)
	case 24578:
		return int32((uint64(x) * 89471205) >> 41)
	case 7681:
		return int32((uint64(x) * 286293876) >> 41)
	case 15362:
		return int32((uint64(x) * 143146938) >> 41)
	default:
		return x / q
	}
}

func modq(t *testing.T, x, q int32) int32 {
	if x >= ((q - 1) ^ 2) {
		t.Fatal("invalid x")
	}
	return x - divq(x, q)*q
}

func testQ(t *testing.T, q int32) {
	max := (q - 1) ^ 2
	for index := int32(0); index < max; index++ {
		m0 := index % q
		m1 := modq(t, index, q)
		if m0 != m1 {
			t.Errorf("%v != %v", m0, m1)
		}
	}
}

func simpleTestQ(t *testing.T, q int32) {
	idx := make([]byte, 8)
	if _, err := rand.Read(idx); err != nil {
		t.Error(err)
	}
	uindex := binary.LittleEndian.Uint32(idx)
	index := int32(uindex)
	if uindex > math.MaxInt32 {
		index = -index
	}
	m0 := index % q
	if m0 < 0 {
		m0 += q
	}

	m1 := smodq(index, q)
	if m0 != m1 {
		t.Errorf("%v != %v", m0, m1)
	}

	m0 = math.MaxInt32 % q
	if m0 < 0 {
		m0 += q
	}
	m1 = smodq(math.MaxInt32, q)
	if m0 != m1 {
		t.Errorf("%v != %v", m0, m1)
	}
}

func TestMod(t *testing.T) {
	testQ(t, 7681)
	testQ(t, 2*7681)
	testQ(t, 12289)
	testQ(t, 2*12289)
	simpleTestQ(t, 7681)
	simpleTestQ(t, 2*7681)
	simpleTestQ(t, 12289)
	simpleTestQ(t, 2*12289)
}
