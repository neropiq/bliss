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

/*
 * Get access to internal tables for Gaussian sampling.
 *
 * These tables are generated by ../tools/tables.
 *
 *  BLISS I:
 *
 *  sigma = 215, ell = 21, precision = 64, 128
 *
 *  BLISS III:
 *
 *  sigma = 250, ell = 21, precision = 64, 128
 *
 *  BLISS IV:
 *
 *  sigma = 271, ell = 22, precision = 64, 128
 *
 */
const sigma100_64 uint16 = 118

const sigmaBits100_64 uint16 = 7

var cbliss100_19_64 = []byte{
	255, 252, 188, 214, 159, 125, 46, 173,
	255, 249, 121, 183, 227, 145, 79, 159,
	255, 242, 243, 154, 88, 243, 134, 131,
	255, 229, 231, 222, 244, 211, 180, 81,
	255, 203, 210, 102, 210, 163, 227, 253,
	255, 151, 175, 112, 51, 161, 106, 255,
	255, 47, 137, 97, 245, 115, 19, 89,
	254, 95, 188, 132, 226, 173, 94, 253,
	252, 194, 29, 229, 39, 67, 183, 19,
	249, 142, 190, 12, 120, 26, 139, 19,
	243, 70, 253, 75, 164, 143, 98, 225,
	231, 47, 216, 141, 26, 100, 205, 190,
	208, 199, 97, 191, 224, 160, 6, 160,
	170, 68, 154, 32, 234, 166, 59, 153,
	113, 63, 47, 21, 245, 237, 14, 2,
	50, 24, 215, 41, 152, 147, 99, 58,
	9, 205, 182, 117, 76, 61, 19, 111,
	0, 96, 28, 33, 249, 67, 99, 84,
	0, 0, 36, 21, 28, 146, 101, 147,
}

const sigma100_128 uint16 = 118
const sigmaBits100_128 uint16 = 7

var cbliss100_19_128 = []byte{
	255, 252, 188, 214, 159, 125, 46, 172, 255, 32, 91, 46, 173, 199, 76, 234,
	255, 249, 121, 183, 227, 145, 79, 159, 110, 13, 154, 126, 20, 124, 36, 86,
	255, 242, 243, 154, 88, 243, 134, 131, 2, 178, 193, 229, 242, 27, 206, 28,
	255, 229, 231, 222, 244, 211, 180, 80, 196, 84, 25, 31, 255, 124, 97, 254,
	255, 203, 210, 102, 210, 163, 227, 253, 24, 89, 133, 179, 171, 209, 210, 104,
	255, 151, 175, 112, 51, 161, 106, 255, 51, 221, 42, 239, 157, 58, 133, 195,
	255, 47, 137, 97, 245, 115, 19, 88, 138, 82, 9, 17, 52, 128, 236, 203,
	254, 95, 188, 132, 226, 173, 94, 252, 149, 81, 28, 22, 22, 140, 246, 134,
	252, 194, 29, 229, 39, 67, 183, 18, 230, 199, 70, 215, 70, 77, 89, 205,
	249, 142, 190, 12, 120, 26, 139, 19, 75, 163, 157, 74, 80, 97, 228, 84,
	243, 70, 253, 75, 164, 143, 98, 224, 179, 210, 196, 181, 166, 3, 95, 87,
	231, 47, 216, 141, 26, 100, 205, 189, 231, 128, 146, 203, 230, 111, 61, 210,
	208, 199, 97, 191, 224, 160, 6, 160, 116, 120, 197, 119, 208, 209, 211, 200,
	170, 68, 154, 32, 234, 166, 59, 153, 67, 161, 63, 248, 26, 7, 237, 245,
	113, 63, 47, 21, 245, 237, 14, 2, 183, 149, 179, 51, 239, 237, 88, 151,
	50, 24, 215, 41, 152, 147, 99, 58, 155, 177, 104, 17, 72, 236, 215, 240,
	9, 205, 182, 117, 76, 61, 19, 111, 74, 160, 18, 228, 212, 2, 105, 241,
	0, 96, 28, 33, 249, 67, 99, 84, 145, 167, 25, 164, 131, 100, 170, 228,
	0, 0, 36, 21, 28, 146, 101, 147, 115, 59, 129, 244, 254, 56, 246, 152,
}

const sigma215_64 uint16 = 254

const sigmaBits215_64 uint16 = 8

var cbliss215_21_64 = []byte{
	255, 255, 75, 191, 247, 94, 30, 52,
	255, 254, 151, 128, 109, 166, 88, 143,
	255, 253, 47, 2, 214, 243, 188, 77,
	255, 250, 94, 13, 156, 120, 121, 217,
	255, 244, 188, 58, 242, 219, 157, 174,
	255, 233, 120, 244, 202, 151, 25, 11,
	255, 210, 243, 229, 18, 88, 50, 240,
	255, 165, 239, 183, 102, 186, 123, 250,
	255, 75, 255, 30, 65, 137, 228, 148,
	254, 152, 124, 205, 192, 136, 102, 79,
	253, 50, 242, 124, 187, 59, 68, 224,
	250, 109, 189, 110, 40, 124, 88, 12,
	244, 250, 133, 6, 3, 13, 45, 9,
	234, 110, 130, 187, 138, 174, 82, 230,
	214, 174, 54, 179, 117, 116, 223, 152,
	180, 7, 186, 2, 112, 3, 68, 13,
	126, 154, 221, 207, 32, 206, 66, 171,
	62, 156, 208, 7, 129, 173, 200, 3,
	15, 80, 84, 209, 213, 2, 107, 160,
	0, 234, 131, 37, 182, 53, 201, 231,
	0, 0, 214, 212, 4, 32, 184, 94,
}

const sigma215_128 uint16 = 254
const sigmaBits215_128 uint16 = 8

var cbliss215_21_128 = []byte{
	255, 255, 75, 191, 247, 94, 30, 51, 147, 246, 89, 59, 99, 248, 26, 128,
	255, 254, 151, 128, 109, 166, 88, 143, 30, 175, 149, 20, 240, 81, 138, 111,
	255, 253, 47, 2, 214, 243, 188, 76, 236, 235, 40, 62, 54, 35, 33, 205,
	255, 250, 94, 13, 156, 120, 121, 216, 255, 120, 90, 11, 39, 232, 120, 111,
	255, 244, 188, 58, 242, 219, 157, 174, 6, 31, 131, 75, 88, 109, 112, 107,
	255, 233, 120, 244, 202, 151, 25, 10, 197, 109, 113, 255, 157, 89, 182, 141,
	255, 210, 243, 229, 18, 88, 50, 239, 130, 192, 12, 167, 62, 254, 211, 202,
	255, 165, 239, 183, 102, 186, 123, 249, 251, 59, 116, 143, 50, 174, 125, 198,
	255, 75, 255, 30, 65, 137, 228, 148, 14, 17, 113, 251, 81, 177, 151, 168,
	254, 152, 124, 205, 192, 136, 102, 79, 5, 62, 214, 95, 36, 223, 7, 20,
	253, 50, 242, 124, 187, 59, 68, 224, 90, 156, 53, 202, 9, 44, 191, 226,
	250, 109, 189, 110, 40, 124, 88, 12, 83, 78, 176, 86, 12, 102, 13, 41,
	244, 250, 133, 6, 3, 13, 45, 9, 120, 121, 150, 237, 69, 190, 62, 16,
	234, 110, 130, 187, 138, 174, 82, 229, 217, 154, 88, 138, 228, 153, 230, 13,
	214, 174, 54, 179, 117, 116, 223, 152, 97, 84, 31, 99, 68, 150, 122, 244,
	180, 7, 186, 2, 112, 3, 68, 13, 123, 133, 244, 184, 232, 216, 133, 18,
	126, 154, 221, 207, 32, 206, 66, 171, 94, 100, 164, 194, 117, 191, 1, 209,
	62, 156, 208, 7, 129, 173, 200, 3, 23, 248, 140, 60, 69, 217, 195, 235,
	15, 80, 84, 209, 213, 2, 107, 160, 1, 152, 43, 130, 93, 95, 241, 218,
	0, 234, 131, 37, 182, 53, 201, 231, 26, 2, 151, 161, 13, 214, 150, 145,
	0, 0, 214, 212, 4, 32, 184, 94, 84, 90, 244, 139, 48, 69, 33, 38,
}

const sigma107_64 uint16 = 126

const sigmaBits107_64 uint16 = 7

var cbliss107_19_64 = []byte{
	255, 253, 35, 133, 139, 148, 197, 17,
	255, 250, 71, 19, 70, 246, 14, 122,
	255, 244, 142, 71, 76, 192, 124, 59,
	255, 233, 29, 17, 145, 228, 243, 107,
	255, 210, 60, 46, 237, 238, 171, 244,
	255, 164, 128, 140, 73, 37, 222, 69,
	255, 73, 33, 204, 110, 3, 191, 89,
	254, 146, 198, 57, 142, 56, 140, 243,
	253, 39, 149, 128, 233, 91, 133, 34,
	250, 87, 67, 159, 177, 213, 79, 151,
	244, 206, 141, 210, 239, 188, 121, 35,
	234, 26, 101, 2, 167, 11, 36, 33,
	214, 20, 67, 97, 133, 197, 100, 38,
	179, 5, 226, 65, 164, 159, 27, 115,
	125, 49, 58, 138, 106, 190, 230, 23,
	61, 57, 28, 162, 162, 158, 76, 252,
	14, 164, 68, 99, 69, 31, 214, 19,
	0, 214, 96, 226, 141, 4, 239, 107,
	0, 0, 179, 134, 31, 110, 118, 129,
}

const sigma107_128 uint16 = 126

const sigmaBits107_128 uint16 = 7

const sigma250_64 uint16 = 295

const sigmaBits250_64 uint16 = 9

var cbliss250_21_64 = []byte{
	255, 255, 122, 95, 16, 128, 14, 195,
	255, 254, 244, 190, 102, 192, 187, 142,
	255, 253, 233, 125, 228, 131, 93, 148,
	255, 251, 211, 0, 37, 9, 199, 245,
	255, 247, 166, 17, 185, 251, 90, 150,
	255, 239, 76, 105, 50, 114, 159, 236,
	255, 222, 153, 233, 85, 187, 45, 205,
	255, 189, 56, 46, 38, 4, 83, 9,
	255, 122, 129, 199, 240, 52, 248, 193,
	254, 245, 73, 44, 68, 229, 150, 75,
	253, 235, 168, 56, 252, 93, 188, 161,
	251, 219, 163, 110, 233, 251, 114, 217,
	247, 200, 110, 236, 134, 237, 213, 112,
	239, 212, 98, 249, 238, 1, 227, 249,
	224, 174, 65, 2, 190, 158, 9, 7,
	197, 49, 104, 97, 61, 210, 19, 116,
	151, 229, 20, 46, 200, 238, 35, 134,
	90, 32, 10, 204, 78, 83, 191, 229,
	31, 186, 139, 154, 90, 155, 17, 8,
	3, 238, 181, 190, 138, 94, 50, 234,
	0, 15, 118, 216, 230, 142, 121, 211,
}

const sigma250_128 uint16 = 295

const sigmaBits250_128 uint16 = 9

var cbliss250_21_128 = []byte{
	255, 255, 122, 95, 16, 128, 14, 195, 60, 90, 166, 191, 205, 26, 144, 204,
	255, 254, 244, 190, 102, 192, 187, 141, 169, 92, 33, 30, 170, 141, 184, 56,
	255, 253, 233, 125, 228, 131, 93, 148, 121, 92, 52, 122, 149, 96, 29, 66,
	255, 251, 211, 0, 37, 9, 199, 244, 213, 217, 122, 205, 171, 200, 198, 5,
	255, 247, 166, 17, 185, 251, 90, 150, 1, 28, 7, 205, 125, 46, 84, 201,
	255, 239, 76, 105, 50, 114, 159, 235, 215, 165, 204, 182, 125, 143, 228, 222,
	255, 222, 153, 233, 85, 187, 45, 204, 236, 229, 38, 180, 20, 161, 7, 167,
	255, 189, 56, 46, 38, 4, 83, 8, 151, 137, 136, 1, 9, 180, 58, 204,
	255, 122, 129, 199, 240, 52, 248, 193, 76, 26, 160, 32, 195, 250, 217, 25,
	254, 245, 73, 44, 68, 229, 150, 74, 228, 74, 124, 249, 123, 94, 108, 127,
	253, 235, 168, 56, 252, 93, 188, 160, 249, 137, 236, 65, 62, 182, 153, 63,
	251, 219, 163, 110, 233, 251, 114, 216, 230, 35, 59, 210, 107, 100, 184, 16,
	247, 200, 110, 236, 134, 237, 213, 111, 240, 149, 109, 22, 216, 213, 237, 145,
	239, 212, 98, 249, 238, 1, 227, 248, 242, 51, 211, 134, 154, 115, 189, 83,
	224, 174, 65, 2, 190, 158, 9, 6, 184, 13, 130, 104, 247, 102, 38, 160,
	197, 49, 104, 97, 61, 210, 19, 115, 208, 54, 91, 27, 209, 227, 33, 26,
	151, 229, 20, 46, 200, 238, 35, 134, 72, 183, 253, 160, 193, 155, 117, 103,
	90, 32, 10, 204, 78, 83, 191, 230, 0, 221, 219, 6, 43, 252, 185, 95,
	31, 186, 139, 154, 90, 155, 17, 9, 42, 139, 40, 111, 246, 175, 4, 15,
	3, 238, 181, 190, 138, 94, 50, 234, 128, 193, 95, 36, 65, 236, 170, 208,
	0, 15, 118, 216, 230, 142, 121, 211, 13, 168, 207, 126, 145, 176, 24, 201,
}

const sigma271_64 uint16 = 320

const sigmaBits271_64 uint16 = 9

var cbliss271_22_64 = []byte{
	255, 255, 142, 111, 102, 2, 141, 88,
	255, 255, 28, 222, 254, 102, 20, 79,
	255, 254, 57, 190, 198, 79, 181, 181,
	255, 252, 115, 128, 178, 170, 212, 166,
	255, 248, 231, 13, 253, 108, 245, 47,
	255, 241, 206, 78, 90, 132, 83, 173,
	255, 227, 157, 102, 46, 28, 61, 128,
	255, 199, 61, 242, 19, 216, 133, 242,
	255, 142, 136, 121, 160, 225, 119, 215,
	255, 29, 67, 61, 254, 49, 27, 152,
	254, 59, 79, 77, 206, 26, 238, 42,
	252, 121, 191, 28, 11, 107, 141, 224,
	248, 255, 234, 37, 109, 169, 103, 26,
	242, 48, 213, 124, 209, 49, 33, 48,
	229, 32, 92, 240, 188, 88, 70, 35,
	205, 18, 234, 94, 14, 226, 237, 77,
	164, 71, 76, 192, 111, 161, 157, 188,
	105, 107, 110, 50, 56, 199, 208, 174,
	43, 105, 77, 122, 127, 254, 146, 221,
	7, 92, 139, 87, 204, 239, 111, 200,
	0, 54, 49, 19, 64, 40, 218, 222,
	0, 0, 11, 120, 189, 135, 113, 62,
}

const sigma271_128 uint16 = 320

const sigmaBits271_128 uint16 = 9

var cbliss271_22_128 = []byte{
	255, 255, 142, 111, 102, 2, 141, 87, 150, 42, 18, 70, 6, 224, 18, 70,
	255, 255, 28, 222, 254, 102, 20, 78, 133, 78, 189, 107, 29, 7, 23, 193,
	255, 254, 57, 190, 198, 79, 181, 181, 108, 75, 142, 145, 45, 238, 193, 29,
	255, 252, 115, 128, 178, 170, 212, 166, 120, 157, 85, 96, 209, 180, 211, 83,
	255, 248, 231, 13, 253, 108, 245, 46, 238, 155, 30, 99, 141, 228, 149, 239,
	255, 241, 206, 78, 90, 132, 83, 172, 228, 179, 119, 115, 240, 51, 216, 6,
	255, 227, 157, 102, 46, 28, 61, 128, 58, 114, 174, 136, 8, 224, 133, 84,
	255, 199, 61, 242, 19, 216, 133, 241, 240, 22, 146, 43, 92, 57, 82, 248,
	255, 142, 136, 121, 160, 225, 119, 214, 241, 44, 159, 34, 133, 118, 96, 60,
	255, 29, 67, 61, 254, 49, 27, 152, 48, 124, 184, 87, 66, 214, 63, 133,
	254, 59, 79, 77, 206, 26, 238, 42, 69, 81, 191, 149, 146, 76, 255, 232,
	252, 121, 191, 28, 11, 107, 141, 223, 234, 42, 226, 50, 138, 102, 16, 97,
	248, 255, 234, 37, 109, 169, 103, 25, 240, 109, 93, 165, 177, 22, 133, 100,
	242, 48, 213, 124, 209, 49, 33, 48, 57, 237, 202, 62, 102, 132, 219, 48,
	229, 32, 92, 240, 188, 88, 70, 34, 179, 94, 244, 70, 25, 123, 76, 140,
	205, 18, 234, 94, 14, 226, 237, 76, 192, 18, 240, 50, 79, 63, 34, 96,
	164, 71, 76, 192, 111, 161, 157, 188, 19, 189, 133, 246, 67, 127, 6, 28,
	105, 107, 110, 50, 56, 199, 208, 174, 16, 95, 153, 106, 217, 198, 194, 179,
	43, 105, 77, 122, 127, 254, 146, 221, 44, 235, 61, 22, 179, 9, 113, 118,
	7, 92, 139, 87, 204, 239, 111, 200, 41, 129, 122, 49, 69, 113, 122, 239,
	0, 54, 49, 19, 64, 40, 218, 222, 60, 82, 186, 246, 64, 155, 184, 47,
	0, 0, 11, 120, 189, 135, 113, 62, 143, 175, 118, 239, 190, 120, 189, 250,
}

/*
 * crufty error checking for now
 * panic for parameters we don't support
 */
func getTable(sigma uint32, ell uint32) []byte {
	if ell < 19 || ell > 22 {
		panic("invalid ell")
	}
	if precision != 64 && precision != 128 {
		panic("precision")
	}
	switch sigma {
	case 100:
		if precision == 64 {
			return cbliss100_19_64
		}
		return cbliss100_19_128
	case 215:
		if precision == 64 {
			return cbliss215_21_64
		}
		return cbliss215_21_128
	case 107:
		if precision == 64 {
			return cbliss107_19_64
		}
		return cbliss100_19_128
	case 250:
		if precision == 64 {
			return cbliss250_21_64
		}
		return cbliss250_21_128
	case 271:
		if precision == 64 {
			return cbliss271_22_64
		}
		return cbliss271_22_128
	default:
		panic("invalid sigma")
	}
}

func getKSigma(sigma uint32) uint16 {
	if precision != 64 && precision != 128 {
		panic("invalid precision")
	}
	switch sigma {
	case 100:
		if precision == 64 {
			return sigma100_64
		}
		return sigma100_128
	case 215:
		if precision == 64 {
			return sigma215_64
		}
		return sigma215_128
	case 107:
		if precision == 64 {
			return sigma107_64
		}
		return sigma107_128
	case 250:
		if precision == 64 {
			return sigma250_64
		}
		return sigma250_128
	case 271:
		if precision == 64 {
			return sigma271_64
		}
		return sigma271_128
	default:
		panic("invalid precision")
	}
}
func getKSigmaBits(sigma uint32) uint16 {
	switch sigma {
	case 100:
		if precision == 64 {
			return sigmaBits100_64
		}
		return sigmaBits100_128
	case 215:
		if precision == 64 {
			return sigmaBits215_64
		}
		return sigmaBits215_128
	case 107:
		if precision == 64 {
			return sigmaBits107_64
		}
		return sigmaBits107_128
	case 250:
		if precision == 64 {
			return sigmaBits250_64
		}
		return sigmaBits250_128
	case 271:
		if precision == 64 {
			return sigmaBits271_64
		}
		return sigmaBits271_128
	default:
		panic("invalid precision")
	}

}
