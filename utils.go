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

//Params for blissB
const (
	SecretBytes    = 256
	PublicKeyBytes = 85
	Bytes          = 128
)

func secureFreePolynomial(ptr *polynomialT) {
	for i := range *ptr {
		(*ptr)[i] = 0
	}
	(*ptr) = nil
}
func secureFreeNTT(ptr *nttT) {
	for i := range *ptr {
		(*ptr)[i] = 0
	}
	(*ptr) = nil
}
func secureFree(ptr *[]int32) {
	for i := range *ptr {
		(*ptr)[i] = 0
	}
	(*ptr) = nil
}

func vectorMaxNorm(v []int32) int32 {
	var max int32

	for i := range v {
		if v[i] > max {
			max = v[i]
		} else if -v[i] > max {
			max = -v[i]
		}
	}

	return max
}

// /*
//  * Scalar product of v1 and v2
//  */
func vectorscalarProduct(v1 []int32, v2 []int32) int32 {
	var sum int32
	for i := range v1 {
		sum += v1[i] * v2[i]
	}

	return sum
}

// /*
//  * Square of the Euclidean norm of v
//  */
func vectorNorm2(v []int32) int32 {
	var sum int32
	for i := range v {
		sum += v[i] * v[i]
	}

	return sum
}
