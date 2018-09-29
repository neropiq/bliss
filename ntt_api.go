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

import "errors"

type polynomialT []int32
type nttT []int32

type nttStateT struct {
	q int32   /* field modulus  */
	n uint32  /* ring size (x^n+1)  */
	w []int32 /* n roots of unity (mod q)  */
	r []int32 /* w[i]/n (mod q)  */
}

func newNtt(kind Kind) *nttStateT {
	param := newBlissParams(kind)
	return &nttStateT{
		q: param.q,
		n: param.n,
		w: param.w,
		r: param.r,
	}
}

func (s *nttStateT) forward(input polynomialT) nttT {
	if s == nil {
		panic("state must not be nil")
	}
	output := ntt32xmu(s.n, s.q, input, s.w) /* multiply by powers of psi                  */
	ntt32FFT(output, s.n, s.q, s.w)          /* result = ntt(input)                        */
	return output
}
func (s *nttStateT) inverse(input nttT) polynomialT {
	output := make(polynomialT, s.n)
	if s == nil {
		panic("state must not be nil")
	}
	for i := uint32(0); i < s.n; i++ {
		output[i] = input[i]
	}

	ntt32FFT(output, s.n, s.q, s.w)          /* result = ntt(input) = inverse ntt(poly) modulo reordering (input = ntt(poly)) */
	output = ntt32xmu(s.n, s.q, output, s.r) /* multiply by powers of psi^-1  */
	ntt32flp(output, s.n, s.q)               /* reorder: result mod q */
	return output
}

func (s *nttStateT) negate(inplace nttT) nttT {
	if s == nil {
		panic("state must not be nil")
	}
	return ntt32cmu(s.n, s.q, inplace, -1)
}

func (s *nttStateT) product(lhs, rhs nttT) nttT {
	if s == nil {
		panic("state must not be nil")
	}
	return ntt32xmu(s.n, s.q, lhs, rhs) /* result = lhs * rhs (pointwise product) */
}

func (s *nttStateT) invertPolynomial(input polynomialT) (nttT, error) {
	if s == nil {
		panic("state must not be nil")
	}
	output := s.forward(input)
	for i := uint32(0); i < s.n; i++ {
		x := output[i]
		if x == 0 {
			return nil, errors.New("not invertible")
		}
		x = ntt32pwr(x, s.q-2, s.q) /* x^(q-2) = inverse of x */
		output[i] = x
	}

	return output, nil
}
func (s *nttStateT) multiply(lhs polynomialT, rhs nttT) polynomialT {
	temp := s.forward(lhs)
	temp = s.product(temp, rhs)
	return s.inverse(temp)
}

/*
 * Simple implementation of modq
 * (could optimize, cf. tests/static/mod.c)
 */
func smodq(x, q int32) int32 {
	if q <= 0 {
		panic("q must be positive")
	}
	y := x % q
	return y + ((y >> 31) & q)
}
