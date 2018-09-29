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

func goodArg(v []int32, n uint32, q int32) bool {
	for i := uint32(0); i < n; i++ {
		if v[i] < 0 || v[i] >= int32(q) {
			return false
		}
	}

	return true
}

// Compute x^n (mod q).
func ntt32pwr(x, n, q int32) int32 {
	var y int32 = 1
	if (n & 1) == 1 {
		y = x
	}

	n >>= 1

	for n > 0 {
		x = (x * x) % q
		if n&1 == 1 {
			y = (x * y) % q
		}
		n >>= 1
	}

	return y
}

/*
 * FFT operation (forward and inverse).
 *
 * BD: modified to use 32-bit arithmetic (don't use ntt32_muln),
 * which is safe if q is less than 2^16.
 * Also forced intermediate results to be between 0 and q-1.
 */
func submod(x, y, q int32) int32 {
	x -= y
	//  return x < 0 ? x + q : x;
	return x + ((x >> 31) & q)
}

func addmod(x, y, q int32) int32 {
	//  x += y;
	//  return x - q >= 0 ? x - q : x;
	x += y - q
	return x + ((x >> 31) & q)
}

func ntt32FFT(v []int32, n uint32, q int32, w []int32) {
	if !goodArg(v, n, q) {
		panic("args are invalid")
	}

	// bit-inverse shuffle
	j := n >> 1
	for i := uint32(1); i < n-1; i++ { // 00..0 and 11..1 remain same
		if i < j {
			v[i], v[j] = v[j], v[i]
		}
		k := n
		for {
			k >>= 1
			j ^= k
			if (j & k) != 0 {
				break
			}
		}
	}

	// main loops
	l := n // BD: avoid division n/i in the loop
	for i := uint32(1); i < n; i <<= 1 {
		//    l = n / i;
		for k := uint32(0); k < n; k += i + i {
			x := v[k+i]
			v[k+i] = submod(v[k], x, q)
			v[k] = addmod(v[k], x, q)
		}

		for j := uint32(1); j < i; j++ {
			y := w[j*l]
			for k := uint32(j); k < n; k += i + i {
				x := (v[k+i] * y) % q
				v[k+i] = submod(v[k], x, q)
				v[k] = addmod(v[k], x, q)
			}
		}
		l >>= 1
	}

	if !goodArg(v, n, q) {
		panic("invalid result")
	}
}

// Elementwise vector product  v = t (*) u.
// BD: modified to use 32 bit arithmetic
func ntt32xmu(n uint32, q int32, t, u []int32) []int32 {
	v := make([]int32, n)

	// multiply each element point-by-point
	for i := uint32(0); i < n; i++ {
		x := (t[i] * u[i]) % q
		v[i] = x + ((x >> 31) & q) // v[i] = if x<0 then x+q else x
	}

	if !goodArg(v, n, q) {
		panic("invalid result")
	}
	return v
}

// Multiply with a scalar  v = t * c.
// BD: modified to use 32 bit arithmetic
func ntt32cmu(n uint32, q int32, t []int32, c int32) []int32 {
	v := make([]int32, n)
	for i := uint32(0); i < n; i++ {
		x := (t[i] * c) % q
		v[i] = x + ((x >> 31) & q) // v[i] = if x<0 then x+q else x
	}
	if !goodArg(v, n, q) {
		panic("invalid result")
	}
	return v
}

// Flip the order.
// BD: removed normalization modulo q, except for v[0] since we assume 0 <= v[i] < q.
func ntt32flp(v []int32, n uint32, q int32) {
	if !goodArg(v, n, q) {
		panic("invalid result")
	}

	for i, j := uint32(1), n-1; i < j; i, j = i+1, j-1 {
		x := v[i]
		v[i] = v[j]
		v[j] = x
	}

	// replace v[0] by q - v[0] if v[0] > 0, keep v[0] = 0 otherwise
	x := q & ((-v[0]) >> 31)
	v[0] = x - v[0]
	if !goodArg(v, n, q) {
		panic("invalid result")
	}
}
