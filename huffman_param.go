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

//This code contains codes from https://github.com/LoCCS/bliss/blob/master/params/params.go

package bliss

var huffEncs = [][][2]int64{
	{ //B0
		{98695, 22}, /*   0: (0,-16) 0000011000000110000111 */
		{24687, 20}, /*   1: (0,-15) 00000110000001101111 */
		{6170, 18},  /*   2: (0,-14) 000001100000011010 */
		{720, 17},   /*   3: (0,-13) 00000001011010000 */
		{387, 14},   /*   4: (0,-12) 00000110000011 */
		{44, 13},    /*   5: (0,-11) 0000000101100 */
		{15, 11},    /*   6: (0,-10) 00000001111 */
		{4, 10},     /*   7: (0,-9) 0000000100 */
		{0, 9},      /*   8: (0,-8) 000000000 */
		{2, 7},      /*   9: (0,-7) 0000010 */
		{3, 6},      /*  10: (0,-6) 000011 */
		{7, 5},      /*  11: (0,-5) 00111 */
		{11, 4},     /*  12: (0,-4) 1011 */
		{2, 4},      /*  13: (0,-3) 0010 */
		{7, 3},      /*  14: (0,-2) 111 */
		{4, 3},      /*  15: (0,-1) 100 */
		{2, 3},      /*  16: (0, 0) 010 */
		{3, 3},      /*  17: (0, 1) 011 */
		{6, 3},      /*  18: (0, 2) 110 */
		{1, 4},      /*  19: (0, 3) 0001 */
		{10, 4},     /*  20: (0, 4) 1010 */
		{6, 5},      /*  21: (0, 5) 00110 */
		{2, 6},      /*  22: (0, 6) 000010 */
		{1, 7},      /*  23: (0, 7) 0000001 */
		{7, 8},      /*  24: (0, 8) 00000111 */
		{3, 10},     /*  25: (0, 9) 0000000011 */
		{14, 11},    /*  26: (0,10) 00000001110 */
		{99, 12},    /*  27: (0,11) 000001100011 */
		{386, 14},   /*  28: (0,12) 00000110000010 */
		{1543, 16},  /*  29: (0,13) 0000011000000111 */
		{6169, 18},  /*  30: (0,14) 000001100000011001 */
		{24686, 20}, /*  31: (0,15) 00000110000001101110 */
		{98694, 22}, /*  32: (0,16) 0000011000000110000110 */

		{12632739, 29}, /*  33: (1,-16) 00000110000001100001010100011 */
		{3158182, 27},  /*  34: (1,-15) 000001100000011000010100110 */
		{789544, 25},   /*  35: (1,-14) 0000011000000110000101000 */
		{197385, 23},   /*  36: (1,-13) 00000110000001100001001 */
		{49345, 21},    /*  37: (1,-12) 000001100000011000001 */
		{12342, 19},    /*  38: (1,-11) 0000011000000110110 */
		{1447, 18},     /*  39: (1,-10) 000000010110100111 */
		{722, 17},      /*  40: (1,-9) 00000001011010010 */
		{770, 15},      /*  41: (1,-8) 000001100000010 */
		{384, 14},      /*  42: (1,-7) 00000110000000 */
		{47, 13},       /*  43: (1,-6) 0000000101111 */
		{98, 12},       /*  44: (1,-5) 000001100010 */
		{9, 12},        /*  45: (1,-4) 000000001001 */
		{13, 11},       /*  46: (1,-3) 00000001101 */
		{10, 11},       /*  47: (1,-2) 00000001010 */
		{27, 10},       /*  48: (1,-1) 0000011011 */
		{25, 10},       /*  49: (1, 0) 0000011001 */
		{26, 10},       /*  50: (1, 1) 0000011010 */
		{5, 11},        /*  51: (1, 2) 00000000101 */
		{12, 11},       /*  52: (1, 3) 00000001100 */
		{8, 12},        /*  53: (1, 4) 000000001000 */
		{97, 12},       /*  54: (1, 5) 000001100001 */
		{46, 13},       /*  55: (1, 6) 0000000101110 */
		{91, 14},       /*  56: (1, 7) 00000001011011 */
		{181, 15},      /*  57: (1, 8) 000000010110101 */
		{721, 17},      /*  58: (1, 9) 00000001011010001 */
		{1446, 18},     /*  59: (1,10) 000000010110100110 */
		{12337, 19},    /*  60: (1,11) 0000011000000110001 */
		{49344, 21},    /*  61: (1,12) 000001100000011000000 */
		{197384, 23},   /*  62: (1,13) 00000110000001100001000 */
		{394775, 24},   /*  63: (1,14) 000001100000011000010111 */
		{3158181, 27},  /*  64: (1,15) 000001100000011000010100101 */
		{12632738, 29}, /*  65: (1,16) 00000110000001100001010100010 */

		{1632561835, 44}, /*  66: (2,-16) 101010101011 */
		{816280916, 43},  /*  67: (2,-15) 10101010100 */
		{204070228, 41},  /*  68: (2,-14) 101010100 */
		{51017556, 39},   /*  69: (2,-13) 1010100 */
		{3233979860, 37}, /*  70: (2,-12) 10100 */
		{808494964, 35},  /*  71: (2,-11) 100 */
		{202123740, 33},  /*  72: (2,-10) 0 */
		{101061869, 32},  /*  73: (2,-9) 00000110000001100001010011101101 */
		{50530933, 31},   /*  74: (2,-8) 0000011000000110000101001110101 */
		{12632789, 29},   /*  75: (2,-7) 00000110000001100001011010101 */
		{12632732, 29},   /*  76: (2,-6) 00000110000001100001010011100 */
		{6316368, 28},    /*  77: (2,-5) 0000011000000110000101010000 */
		{3158196, 27},    /*  78: (2,-4) 000001100000011000010110100 */
		{3158180, 27},    /*  79: (2,-3) 000001100000011000010100100 */
		{1579097, 26},    /*  80: (2,-2) 00000110000001100001011001 */
		{1579095, 26},    /*  81: (2,-1) 00000110000001100001010111 */
		{1579093, 26},    /*  82: (2, 0) 00000110000001100001010101 */
		{1579094, 26},    /*  83: (2, 1) 00000110000001100001010110 */
		{1579096, 26},    /*  84: (2, 2) 00000110000001100001011000 */
		{1579099, 26},    /*  85: (2, 3) 00000110000001100001011011 */
		{3158185, 27},    /*  86: (2, 4) 000001100000011000010101001 */
		{6316367, 28},    /*  87: (2, 5) 0000011000000110000101001111 */
		{6316395, 28},    /*  88: (2, 6) 0000011000000110000101101011 */
		{12632788, 29},   /*  89: (2, 7) 00000110000001100001011010100 */
		{50530932, 31},   /*  90: (2, 8) 0000011000000110000101001110100 */
		{101061868, 32},  /*  91: (2, 9) 00000110000001100001010011101100 */
		{101061871, 32},  /*  92: (2,10) 00000110000001100001010011101111 */
		{404247483, 34},  /*  93: (2,11) 11 */
		{1616989931, 36}, /*  94: (2,12) 1011 */
		{2172992427, 38}, /*  95: (2,13) 101011 */
		{102035115, 40},  /*  96: (2,14) 10101011 */
		{408140459, 42},  /*  97: (2,15) 1010101011 */
		{1632561834, 44}, /*  98: (2,16) 101010101010 */
	},
	{ //B1
		{1665896, 21}, /*   0: (0,-2) 110010110101101101000 */
		{24, 5},       /*   1: (0,-1) 11000 */
		{0, 1},        /*   2: (0, 0) 0 */
		{13, 4},       /*   3: (0, 1) 1101 */
		{832949, 20},  /*   4: (0, 2) 11001011010110110101 */

		{6663588, 23}, /*   5: (1,-2) 11001011010110110100100 */
		{100, 7},      /*   6: (1,-1) 1100100 */
		{2, 2},        /*   7: (1, 0) 10 */
		{51, 6},       /*   8: (1, 1) 110011 */
		{3331795, 22}, /*   9: (1, 2) 1100101101011011010011 */

		{53308712, 26}, /*  10: (2,-2) 11001011010110110100101000 */
		{812, 10},      /*  11: (2,-1) 1100101100 */
		{7, 3},         /*  12: (2, 0) 111 */
		{407, 9},       /*  13: (2, 1) 110010111 */
		{26654359, 25}, /*  14: (2, 2) 1100101101011011010010111 */

		{213234852, 28}, /*  15: (3,-2) 1100101101011011010010100100 */
		{3252, 12},      /*  16: (3,-1) 110010110100 */
		{202, 8},        /*  17: (3, 0) 11001010 */
		{1627, 11},      /*  18: (3, 1) 11001011011 */
		{106617427, 27}, /*  19: (3, 2) 110010110101101101001010011 */

		{3411757660, 32}, /*  20: (4,-2) 11001011010110110100101001011100 */
		{26028, 15},      /*  21: (4,-1) 110010110101100 */
		{6506, 13},       /*  22: (4, 0) 1100101101010 */
		{13015, 14},      /*  23: (4, 1) 11001011010111 */
		{1705878831, 31}, /*  24: (4, 2) 1100101101011011010010100101111 */

		{762128756, 34},  /*  25: (5,-2) 00 */
		{208236, 18},     /*  26: (5,-1) 110010110101101100 */
		{52058, 16},      /*  27: (5, 0) 1100101101011010 */
		{104119, 17},     /*  28: (5, 1) 11001011010110111 */
		{2528548027, 33}, /*  29: (5, 2) 1 */

		{3048515028, 36}, /*  30: (6,-2) 0100 */
		{26654358, 25},   /*  31: (6,-1) 1100101101011011010010110 */
		{416475, 19},     /*  32: (6, 0) 1100101101011011011 */
		{26654357, 25},   /*  33: (6, 1) 1100101101011011010010101 */
		{1524257515, 35}, /*  34: (6, 2) 011 */

		{3604125524, 38}, /*  35: (7,-2) 010100 */
		{1705878829, 31}, /*  36: (7,-1) 1100101101011011010010100101101 */
		{426469706, 29},  /*  37: (7, 0) 11001011010110110100101001010 */
		{1705878828, 31}, /*  38: (7, 1) 1100101101011011010010100101100 */
		{1802062763, 37}, /*  39: (7, 2) 01011 */

		{3063200425, 41}, /*  40: (8,-2) 010101001 */
		{3063200424, 41}, /*  41: (8,-1) 010101000 */
		{1531600215, 40}, /*  42: (8, 0) 01010111 */
		{1531600214, 40}, /*  43: (8, 1) 01010110 */
		{1531600213, 40}, /*  44: (8, 2) 01010101 */
	},
	{ //B2
		{24, 5}, /*   0: (0,-1) 11000 */
		{0, 1},  /*   1: (0, 0) 0 */
		{13, 4}, /*   2: (0, 1) 1101 */

		{100, 7}, /*   3: (1,-1) 1100100 */
		{2, 2},   /*   4: (1, 0) 10 */
		{51, 6},  /*   5: (1, 1) 110011 */

		{404, 9}, /*   6: (2,-1) 110010100 */
		{7, 3},   /*   7: (2, 0) 111 */
		{203, 8}, /*   8: (2, 1) 11001011 */

		{3244, 12}, /*   9: (3,-1) 110010101100 */
		{810, 10},  /*  10: (3, 0) 1100101010 */
		{1623, 11}, /*  11: (3, 1) 11001010111 */

		{51921, 16}, /*  12: (4,-1) 1100101011010001 */
		{51920, 16}, /*  13: (4, 0) 1100101011010000 */
		{25967, 15}, /*  14: (4, 1) 110010101101111 */

		{25966, 15}, /*  15: (5,-1) 110010101101110 */
		{25965, 15}, /*  16: (5, 0) 110010101101101 */
		{25964, 15}, /*  17: (5, 1) 110010101101100 */

		{25963, 15}, /*  18: (6,-1) 110010101101011 */
		{25962, 15}, /*  19: (6, 0) 110010101101010 */
		{25961, 15}, /*  20: (6, 1) 110010101101001 */
	},
	{ //B3
		{480170, 21}, /*   0: (0,-3) 001110101001110101010 */
		{119, 9},     /*   1: (0,-2) 001110111 */
		{3, 3},       /*   2: (0,-1) 011 */
		{1, 1},       /*   3: (0, 0) 1 */
		{2, 3},       /*   4: (0, 1) 010 */
		{118, 9},     /*   5: (0, 2) 001110110 */
		{240087, 20}, /*   6: (0, 3) 00111010100111010111 */

		{1920684, 23}, /*   7: (1,-3) 00111010100111010101100 */
		{936, 12},     /*   8: (1,-2) 001110101000 */
		{5, 5},        /*   9: (1,-1) 00101 */
		{0, 3},        /*  10: (1, 0) 000 */
		{4, 5},        /*  11: (1, 1) 00100 */
		{471, 11},     /*  12: (1, 2) 00111010111 */
		{960347, 22},  /*  13: (1, 3) 0011101010011101011011 */

		{7682740, 25}, /*  14: (2,-3) 0011101010011101010110100 */
		{3749, 14},    /*  15: (2,-2) 00111010100101 */
		{28, 7},       /*  16: (2,-1) 0011100 */
		{6, 5},        /*  17: (2, 0) 00110 */
		{15, 6},       /*  18: (2, 1) 001111 */
		{3748, 14},    /*  19: (2, 2) 00111010100100 */
		{3841371, 24}, /*  20: (2, 3) 001110101001110101011011 */

		{61461930, 28}, /*  21: (3,-3) 0011101010011101010110101010 */
		{60020, 18},    /*  22: (3,-2) 001110101001110100 */
		{470, 11},      /*  23: (3,-1) 00111010110 */
		{116, 9},       /*  24: (3, 0) 001110100 */
		{469, 11},      /*  25: (3, 1) 00111010101 */
		{30011, 17},    /*  26: (3, 2) 00111010100111011 */
		{61461929, 28}, /*  27: (3, 3) 0011101010011101010110101001 */

		{983390900, 32}, /*  28: (4,-3) 00111010100111010101101010110100 */
		{960346, 22},    /*  29: (4,-2) 0011101010011101011010 */
		{15004, 16},     /*  30: (4,-1) 0011101010011100 */
		{3750, 14},      /*  31: (4, 0) 00111010100110 */
		{7503, 15},      /*  32: (4, 1) 001110101001111 */
		{960345, 22},    /*  33: (4, 2) 0011101010011101011001 */
		{491695451, 31}, /*  34: (4, 3) 0011101010011101010110101011011 */

		{2849352532, 36}, /*  35: (5,-3) 0100 */
		{61461928, 28},   /*  36: (5,-2) 0011101010011101010110101000 */
		{960344, 22},     /*  37: (5,-1) 0011101010011101011000 */
		{240084, 20},     /*  38: (5, 0) 00111010100111010100 */
		{960343, 22},     /*  39: (5, 1) 0011101010011101010111 */
		{30730967, 27},   /*  40: (5, 2) 001110101001110101011010111 */
		{3572159915, 35}, /*  41: (5, 3) 011 */

		{1403737771, 37}, /*  42: (6,-3) 01011 */
		{3933563604, 34}, /*  43: (6,-2) 00 */
		{245847724, 30},  /*  44: (6,-1) 001110101001110101011010101100 */
		{30730966, 27},   /*  45: (6, 0) 001110101001110101011010110 */
		{122923863, 29},  /*  46: (6, 1) 00111010100111010101101010111 */
		{1966781803, 33}, /*  47: (6, 2) 1 */
		{1403737770, 37}, /*  48: (6, 3) 01010 */
	},
	{ //B4

		{16073140, 24}, /*   0: (0,-6) 111101010100000110110100 */
		{125570, 17},   /*   1: (0,-5) 11110101010000010 */
		{1966, 11},     /*   2: (0,-4) 11110101110 */
		{72, 8},        /*   3: (0,-3) 01001000 */
		{14, 4},        /*   4: (0,-2) 1110 */
		{1, 3},         /*   5: (0,-1) 001 */
		{2, 2},         /*   6: (0, 0) 10 */
		{0, 3},         /*   7: (0, 1) 000 */
		{7, 4},         /*   8: (0, 2) 0111 */
		{123, 7},       /*   9: (0, 3) 1111011 */
		{1965, 11},     /*  10: (0, 4) 11110101101 */
		{125569, 17},   /*  11: (0, 5) 11110101010000001 */
		{16073139, 24}, /*  12: (0, 6) 111101010100000110110011 */

		{32146283, 25}, /*  13: (1,-6) 1111010101000001101101011 */
		{502272, 19},   /*  14: (1,-5) 1111010101000000000 */
		{3934, 12},     /*  15: (1,-4) 111101011110 */
		{147, 9},       /*  16: (1,-3) 010010011 */
		{16, 6},        /*  17: (1,-2) 010000 */
		{6, 4},         /*  18: (1,-1) 0110 */
		{6, 3},         /*  19: (1, 0) 110 */
		{5, 4},         /*  20: (1, 1) 0101 */
		{31, 5},        /*  21: (1, 2) 11111 */
		{146, 9},       /*  22: (1, 3) 010010010 */
		{3925, 12},     /*  23: (1, 4) 111101010101 */
		{251143, 18},   /*  24: (1, 5) 111101010100000111 */
		{32146282, 25}, /*  25: (1, 6) 1111010101000001101101010 */

		{257170216, 28}, /*  26: (2,-6) 1111010101000001101100101000 */
		{2009097, 21},   /*  27: (2,-5) 111101010100000001001 */
		{31394, 15},     /*  28: (2,-4) 111101010100010 */
		{1961, 11},      /*  29: (2,-3) 11110101001 */
		{75, 8},         /*  30: (2,-2) 01001011 */
		{60, 6},         /*  31: (2,-1) 111100 */
		{17, 6},         /*  32: (2, 0) 010001 */
		{19, 6},         /*  33: (2, 1) 010011 */
		{74, 8},         /*  34: (2, 2) 01001010 */
		{1960, 11},      /*  35: (2, 3) 11110101000 */
		{31393, 15},     /*  36: (2, 4) 111101010100001 */
		{2009096, 21},   /*  37: (2, 5) 111101010100000001000 */
		{128585111, 27}, /*  38: (2, 6) 111101010100000110110010111 */

		{2057361764, 31}, /*  39: (3,-6) 1111010101000001101100101100100 */
		{16073143, 24},   /*  40: (3,-5) 111101010100000110110111 */
		{502284, 19},     /*  41: (3,-4) 1111010101000001100 */
		{15699, 14},      /*  42: (3,-3) 11110101010011 */
		{1964, 11},       /*  43: (3,-2) 11110101100 */
		{977, 10},        /*  44: (3,-1) 1111010001 */
		{489, 9},         /*  45: (3, 0) 111101001 */
		{976, 10},        /*  46: (3, 1) 1111010000 */
		{1963, 11},       /*  47: (3, 2) 11110101011 */
		{15698, 14},      /*  48: (3, 3) 11110101010010 */
		{502275, 19},     /*  49: (3, 4) 1111010101000000011 */
		{16073142, 24},   /*  50: (3, 5) 111101010100000110110110 */
		{1028680883, 30}, /*  51: (3, 6) 111101010100000110110010110011 */

		{1411067048, 36}, /*  52: (4,-6) 1000 */
		{514340439, 29},  /*  53: (4,-5) 11110101010000011011001010111 */
		{16073137, 24},   /*  54: (4,-4) 111101010100000110110001 */
		{1004547, 20},    /*  55: (4,-3) 11110101010000000011 */
		{62791, 16},      /*  56: (4,-2) 1111010101000111 */
		{15741, 14},      /*  57: (4,-1) 11110101111101 */
		{7871, 13},       /*  58: (4, 0) 1111010111111 */
		{15740, 14},      /*  59: (4, 1) 11110101111100 */
		{62790, 16},      /*  60: (4, 2) 1111010101000110 */
		{1004546, 20},    /*  61: (4, 3) 11110101010000000010 */
		{16073136, 24},   /*  62: (4, 4) 111101010100000110110000 */
		{514340438, 29},  /*  63: (4, 5) 11110101010000011011001010110 */
		{2853017175, 35}, /*  64: (4, 6) 111 */

		{1102236309, 40}, /*  65: (5,-6) 10010101 */
		{2853017174, 35}, /*  66: (5,-5) 110 */
		{1028680871, 30}, /*  67: (5,-4) 111101010100000110110010100111 */
		{64292553, 26},   /*  68: (5,-3) 11110101010000011011001001 */
		{4018287, 22},    /*  69: (5,-2) 1111010101000001101111 */
		{2009099, 21},    /*  70: (5,-1) 111101010100000001011 */
		{1004570, 20},    /*  71: (5, 0) 11110101010000011010 */
		{2009098, 21},    /*  72: (5, 1) 111101010100000001010 */
		{4018286, 22},    /*  73: (5, 2) 1111010101000001101110 */
		{64292552, 26},   /*  74: (5, 3) 11110101010000011011001000 */
		{1028680870, 30}, /*  75: (5, 4) 111101010100000110110010100110 */
		{2853017173, 35}, /*  76: (5, 5) 101 */
		{1102236308, 40}, /*  77: (5, 6) 10010100 */

		{113977947, 42},  /*  78: (6,-6) 1001011011 */
		{2204472620, 41}, /*  79: (6,-5) 100101100 */
		{1349300900, 38}, /*  80: (6,-4) 100100 */
		{3934479764, 33}, /*  81: (6,-3) 0 */
		{1028680881, 30}, /*  82: (6,-2) 111101010100000110110010110001 */
		{514340434, 29},  /*  83: (6,-1) 11110101010000011011001010010 */
		{257170218, 28},  /*  84: (6, 0) 1111010101000001101100101010 */
		{257170221, 28},  /*  85: (6, 1) 1111010101000001101100101101 */
		{1028680880, 30}, /*  86: (6, 2) 111101010100000110110010110000 */
		{4114723531, 32}, /*  87: (6, 3) 11110101010000011011001011001011 */
		{2822134099, 37}, /*  88: (6, 4) 10011 */
		{1102236311, 40}, /*  89: (6, 5) 10010111 */
		{113977946, 42},  /*  90: (6, 6) 1001011010 */
	},
}

var huffDecs = [][][3]int{
	{ //B0
		{1, 188, -1},   /*   0: */
		{2, 185, -1},   /*   1: */
		{3, 180, -1},   /*   2: */
		{4, 179, -1},   /*   3: */
		{5, 176, -1},   /*   4: */
		{6, 49, -1},    /*   5: */
		{7, 48, -1},    /*   6: */
		{8, 17, -1},    /*   7: */
		{9, 10, -1},    /*   8: */
		{-1, -1, 8},    /*   9: (0,-8)  9 bits */
		{11, 16, -1},   /*  10: */
		{12, 15, -1},   /*  11: */
		{13, 14, -1},   /*  12: */
		{-1, -1, 53},   /*  13: (1, 4) 12 bits */
		{-1, -1, 45},   /*  14: (1,-4) 12 bits */
		{-1, -1, 51},   /*  15: (1, 2) 11 bits */
		{-1, -1, 25},   /*  16: (0, 9) 10 bits */
		{18, 41, -1},   /*  17: */
		{19, 20, -1},   /*  18: */
		{-1, -1, 7},    /*  19: (0,-9) 10 bits */
		{21, 22, -1},   /*  20: */
		{-1, -1, 47},   /*  21: (1,-2) 11 bits */
		{23, 38, -1},   /*  22: */
		{24, 25, -1},   /*  23: */
		{-1, -1, 5},    /*  24: (0,-11) 13 bits */
		{26, 37, -1},   /*  25: */
		{27, 36, -1},   /*  26: */
		{28, 31, -1},   /*  27: */
		{29, 30, -1},   /*  28: */
		{-1, -1, 3},    /*  29: (0,-13) 17 bits */
		{-1, -1, 58},   /*  30: (1, 9) 17 bits */
		{32, 33, -1},   /*  31: */
		{-1, -1, 40},   /*  32: (1,-9) 17 bits */
		{34, 35, -1},   /*  33: */
		{-1, -1, 59},   /*  34: (1,10) 18 bits */
		{-1, -1, 39},   /*  35: (1,-10) 18 bits */
		{-1, -1, 57},   /*  36: (1, 8) 15 bits */
		{-1, -1, 56},   /*  37: (1, 7) 14 bits */
		{39, 40, -1},   /*  38: */
		{-1, -1, 55},   /*  39: (1, 6) 13 bits */
		{-1, -1, 43},   /*  40: (1,-6) 13 bits */
		{42, 45, -1},   /*  41: */
		{43, 44, -1},   /*  42: */
		{-1, -1, 52},   /*  43: (1, 3) 11 bits */
		{-1, -1, 46},   /*  44: (1,-3) 11 bits */
		{46, 47, -1},   /*  45: */
		{-1, -1, 26},   /*  46: (0,10) 11 bits */
		{-1, -1, 6},    /*  47: (0,-10) 11 bits */
		{-1, -1, 23},   /*  48: (0, 7)  7 bits */
		{50, 51, -1},   /*  49: */
		{-1, -1, 9},    /*  50: (0,-7)  7 bits */
		{52, 175, -1},  /*  51: */
		{53, 172, -1},  /*  52: */
		{54, 171, -1},  /*  53: */
		{55, 168, -1},  /*  54: */
		{56, 167, -1},  /*  55: */
		{57, 164, -1},  /*  56: */
		{58, 59, -1},   /*  57: */
		{-1, -1, 42},   /*  58: (1,-7) 14 bits */
		{60, 61, -1},   /*  59: */
		{-1, -1, 41},   /*  60: (1,-8) 15 bits */
		{62, 163, -1},  /*  61: */
		{63, 156, -1},  /*  62: */
		{64, 155, -1},  /*  63: */
		{65, 154, -1},  /*  64: */
		{66, 69, -1},   /*  65: */
		{67, 68, -1},   /*  66: */
		{-1, -1, 61},   /*  67: (1,12) 21 bits */
		{-1, -1, 37},   /*  68: (1,-12) 21 bits */
		{70, 151, -1},  /*  69: */
		{71, 74, -1},   /*  70: */
		{72, 73, -1},   /*  71: */
		{-1, -1, 62},   /*  72: (1,13) 23 bits */
		{-1, -1, 36},   /*  73: (1,-13) 23 bits */
		{75, 136, -1},  /*  74: */
		{76, 123, -1},  /*  75: */
		{77, 78, -1},   /*  76: */
		{-1, -1, 35},   /*  77: (1,-14) 25 bits */
		{79, 82, -1},   /*  78: */
		{80, 81, -1},   /*  79: */
		{-1, -1, 79},   /*  80: (2,-3) 27 bits */
		{-1, -1, 64},   /*  81: (1,15) 27 bits */
		{83, 84, -1},   /*  82: */
		{-1, -1, 34},   /*  83: (1,-15) 27 bits */
		{85, 122, -1},  /*  84: */
		{86, 87, -1},   /*  85: */
		{-1, -1, 76},   /*  86: (2,-6) 29 bits */
		{88, 91, -1},   /*  87: */
		{89, 90, -1},   /*  88: */
		{-1, -1, 90},   /*  89: (2, 8) 31 bits */
		{-1, -1, 74},   /*  90: (2,-8) 31 bits */
		{92, 95, -1},   /*  91: */
		{93, 94, -1},   /*  92: */
		{-1, -1, 91},   /*  93: (2, 9) 32 bits */
		{-1, -1, 73},   /*  94: (2,-9) 32 bits */
		{96, 121, -1},  /*  95: */
		{97, 98, -1},   /*  96: */
		{-1, -1, 72},   /*  97: (2,-10) 33 bits */
		{99, 120, -1},  /*  98: */
		{100, 101, -1}, /*  99: */
		{-1, -1, 71},   /* 100: (2,-11) 35 bits */
		{102, 119, -1}, /* 101: */
		{103, 104, -1}, /* 102: */
		{-1, -1, 70},   /* 103: (2,-12) 37 bits */
		{105, 118, -1}, /* 104: */
		{106, 107, -1}, /* 105: */
		{-1, -1, 69},   /* 106: (2,-13) 39 bits */
		{108, 117, -1}, /* 107: */
		{109, 110, -1}, /* 108: */
		{-1, -1, 68},   /* 109: (2,-14) 41 bits */
		{111, 116, -1}, /* 110: */
		{112, 113, -1}, /* 111: */
		{-1, -1, 67},   /* 112: (2,-15) 43 bits */
		{114, 115, -1}, /* 113: */
		{-1, -1, 98},   /* 114: (2,16) 44 bits */
		{-1, -1, 66},   /* 115: (2,-16) 44 bits */
		{-1, -1, 97},   /* 116: (2,15) 42 bits */
		{-1, -1, 96},   /* 117: (2,14) 40 bits */
		{-1, -1, 95},   /* 118: (2,13) 38 bits */
		{-1, -1, 94},   /* 119: (2,12) 36 bits */
		{-1, -1, 93},   /* 120: (2,11) 34 bits */
		{-1, -1, 92},   /* 121: (2,10) 32 bits */
		{-1, -1, 87},   /* 122: (2, 5) 28 bits */
		{124, 133, -1}, /* 123: */
		{125, 132, -1}, /* 124: */
		{126, 131, -1}, /* 125: */
		{127, 128, -1}, /* 126: */
		{-1, -1, 77},   /* 127: (2,-5) 28 bits */
		{129, 130, -1}, /* 128: */
		{-1, -1, 65},   /* 129: (1,16) 29 bits */
		{-1, -1, 33},   /* 130: (1,-16) 29 bits */
		{-1, -1, 86},   /* 131: (2, 4) 27 bits */
		{-1, -1, 82},   /* 132: (2, 0) 26 bits */
		{134, 135, -1}, /* 133: */
		{-1, -1, 83},   /* 134: (2, 1) 26 bits */
		{-1, -1, 81},   /* 135: (2,-1) 26 bits */
		{137, 150, -1}, /* 136: */
		{138, 141, -1}, /* 137: */
		{139, 140, -1}, /* 138: */
		{-1, -1, 84},   /* 139: (2, 2) 26 bits */
		{-1, -1, 80},   /* 140: (2,-2) 26 bits */
		{142, 149, -1}, /* 141: */
		{143, 144, -1}, /* 142: */
		{-1, -1, 78},   /* 143: (2,-4) 27 bits */
		{145, 148, -1}, /* 144: */
		{146, 147, -1}, /* 145: */
		{-1, -1, 89},   /* 146: (2, 7) 29 bits */
		{-1, -1, 75},   /* 147: (2,-7) 29 bits */
		{-1, -1, 88},   /* 148: (2, 6) 28 bits */
		{-1, -1, 85},   /* 149: (2, 3) 26 bits */
		{-1, -1, 63},   /* 150: (1,14) 24 bits */
		{152, 153, -1}, /* 151: */
		{-1, -1, 32},   /* 152: (0,16) 22 bits */
		{-1, -1, 0},    /* 153: (0,-16) 22 bits */
		{-1, -1, 60},   /* 154: (1,11) 19 bits */
		{-1, -1, 30},   /* 155: (0,14) 18 bits */
		{157, 158, -1}, /* 156: */
		{-1, -1, 2},    /* 157: (0,-14) 18 bits */
		{159, 160, -1}, /* 158: */
		{-1, -1, 38},   /* 159: (1,-11) 19 bits */
		{161, 162, -1}, /* 160: */
		{-1, -1, 31},   /* 161: (0,15) 20 bits */
		{-1, -1, 1},    /* 162: (0,-15) 20 bits */
		{-1, -1, 29},   /* 163: (0,13) 16 bits */
		{165, 166, -1}, /* 164: */
		{-1, -1, 28},   /* 165: (0,12) 14 bits */
		{-1, -1, 4},    /* 166: (0,-12) 14 bits */
		{-1, -1, 54},   /* 167: (1, 5) 12 bits */
		{169, 170, -1}, /* 168: */
		{-1, -1, 44},   /* 169: (1,-5) 12 bits */
		{-1, -1, 27},   /* 170: (0,11) 12 bits */
		{-1, -1, 49},   /* 171: (1, 0) 10 bits */
		{173, 174, -1}, /* 172: */
		{-1, -1, 50},   /* 173: (1, 1) 10 bits */
		{-1, -1, 48},   /* 174: (1,-1) 10 bits */
		{-1, -1, 24},   /* 175: (0, 8)  8 bits */
		{177, 178, -1}, /* 176: */
		{-1, -1, 22},   /* 177: (0, 6)  6 bits */
		{-1, -1, 10},   /* 178: (0,-6)  6 bits */
		{-1, -1, 19},   /* 179: (0, 3)  4 bits */
		{181, 182, -1}, /* 180: */
		{-1, -1, 13},   /* 181: (0,-3)  4 bits */
		{183, 184, -1}, /* 182: */
		{-1, -1, 21},   /* 183: (0, 5)  5 bits */
		{-1, -1, 11},   /* 184: (0,-5)  5 bits */
		{186, 187, -1}, /* 185: */
		{-1, -1, 16},   /* 186: (0, 0)  3 bits */
		{-1, -1, 17},   /* 187: (0, 1)  3 bits */
		{189, 194, -1}, /* 188: */
		{190, 191, -1}, /* 189: */
		{-1, -1, 15},   /* 190: (0,-1)  3 bits */
		{192, 193, -1}, /* 191: */
		{-1, -1, 20},   /* 192: (0, 4)  4 bits */
		{-1, -1, 12},   /* 193: (0,-4)  4 bits */
		{195, 196, -1}, /* 194: */
		{-1, -1, 18},   /* 195: (0, 2)  3 bits */
		{-1, -1, 14},   /* 196: (0,-2)  3 bits */
	},
	{ //B1
		{1, 2, -1},   /*   0: */
		{-1, -1, 2},  /*   1: (0, 0)  1 bit  */
		{3, 4, -1},   /*   2: */
		{-1, -1, 7},  /*   3: (1, 0)  2 bits */
		{5, 88, -1},  /*   4: */
		{6, 87, -1},  /*   5: */
		{7, 8, -1},   /*   6: */
		{-1, -1, 1},  /*   7: (0,-1)  5 bits */
		{9, 86, -1},  /*   8: */
		{10, 11, -1}, /*   9: */
		{-1, -1, 6},  /*  10: (1,-1)  7 bits */
		{12, 13, -1}, /*  11: */
		{-1, -1, 17}, /*  12: (3, 0)  8 bits */
		{14, 85, -1}, /*  13: */
		{15, 16, -1}, /*  14: */
		{-1, -1, 11}, /*  15: (2,-1) 10 bits */
		{17, 84, -1}, /*  16: */
		{18, 19, -1}, /*  17: */
		{-1, -1, 16}, /*  18: (3,-1) 12 bits */
		{20, 21, -1}, /*  19: */
		{-1, -1, 22}, /*  20: (4, 0) 13 bits */
		{22, 83, -1}, /*  21: */
		{23, 24, -1}, /*  22: */
		{-1, -1, 21}, /*  23: (4,-1) 15 bits */
		{25, 26, -1}, /*  24: */
		{-1, -1, 27}, /*  25: (5, 0) 16 bits */
		{27, 82, -1}, /*  26: */
		{28, 29, -1}, /*  27: */
		{-1, -1, 26}, /*  28: (5,-1) 18 bits */
		{30, 81, -1}, /*  29: */
		{31, 80, -1}, /*  30: */
		{32, 33, -1}, /*  31: */
		{-1, -1, 0},  /*  32: (0,-2) 21 bits */
		{34, 79, -1}, /*  33: */
		{35, 36, -1}, /*  34: */
		{-1, -1, 5},  /*  35: (1,-2) 23 bits */
		{37, 76, -1}, /*  36: */
		{38, 75, -1}, /*  37: */
		{39, 40, -1}, /*  38: */
		{-1, -1, 10}, /*  39: (2,-2) 26 bits */
		{41, 74, -1}, /*  40: */
		{42, 43, -1}, /*  41: */
		{-1, -1, 15}, /*  42: (3,-2) 28 bits */
		{44, 45, -1}, /*  43: */
		{-1, -1, 37}, /*  44: (7, 0) 29 bits */
		{46, 49, -1}, /*  45: */
		{47, 48, -1}, /*  46: */
		{-1, -1, 38}, /*  47: (7, 1) 31 bits */
		{-1, -1, 36}, /*  48: (7,-1) 31 bits */
		{50, 73, -1}, /*  49: */
		{51, 52, -1}, /*  50: */
		{-1, -1, 20}, /*  51: (4,-2) 32 bits */
		{53, 72, -1}, /*  52: */
		{54, 55, -1}, /*  53: */
		{-1, -1, 25}, /*  54: (5,-2) 34 bits */
		{56, 71, -1}, /*  55: */
		{57, 58, -1}, /*  56: */
		{-1, -1, 30}, /*  57: (6,-2) 36 bits */
		{59, 70, -1}, /*  58: */
		{60, 61, -1}, /*  59: */
		{-1, -1, 35}, /*  60: (7,-2) 38 bits */
		{62, 67, -1}, /*  61: */
		{63, 66, -1}, /*  62: */
		{64, 65, -1}, /*  63: */
		{-1, -1, 41}, /*  64: (8,-1) 41 bits */
		{-1, -1, 40}, /*  65: (8,-2) 41 bits */
		{-1, -1, 44}, /*  66: (8, 2) 40 bits */
		{68, 69, -1}, /*  67: */
		{-1, -1, 43}, /*  68: (8, 1) 40 bits */
		{-1, -1, 42}, /*  69: (8, 0) 40 bits */
		{-1, -1, 39}, /*  70: (7, 2) 37 bits */
		{-1, -1, 34}, /*  71: (6, 2) 35 bits */
		{-1, -1, 29}, /*  72: (5, 2) 33 bits */
		{-1, -1, 24}, /*  73: (4, 2) 31 bits */
		{-1, -1, 19}, /*  74: (3, 2) 27 bits */
		{-1, -1, 33}, /*  75: (6, 1) 25 bits */
		{77, 78, -1}, /*  76: */
		{-1, -1, 31}, /*  77: (6,-1) 25 bits */
		{-1, -1, 14}, /*  78: (2, 2) 25 bits */
		{-1, -1, 9},  /*  79: (1, 2) 22 bits */
		{-1, -1, 4},  /*  80: (0, 2) 20 bits */
		{-1, -1, 32}, /*  81: (6, 0) 19 bits */
		{-1, -1, 28}, /*  82: (5, 1) 17 bits */
		{-1, -1, 23}, /*  83: (4, 1) 14 bits */
		{-1, -1, 18}, /*  84: (3, 1) 11 bits */
		{-1, -1, 13}, /*  85: (2, 1)  9 bits */
		{-1, -1, 8},  /*  86: (1, 1)  6 bits */
		{-1, -1, 3},  /*  87: (0, 1)  4 bits */
		{-1, -1, 12}, /*  88: (2, 0)  3 bits */
	},
	{ //B2
		{1, 2, -1},   /*   0: */
		{-1, -1, 1},  /*   1: (0, 0)  1 bit  */
		{3, 4, -1},   /*   2: */
		{-1, -1, 4},  /*   3: (1, 0)  2 bits */
		{5, 40, -1},  /*   4: */
		{6, 39, -1},  /*   5: */
		{7, 8, -1},   /*   6: */
		{-1, -1, 0},  /*   7: (0,-1)  5 bits */
		{9, 38, -1},  /*   8: */
		{10, 11, -1}, /*   9: */
		{-1, -1, 3},  /*  10: (1,-1)  7 bits */
		{12, 37, -1}, /*  11: */
		{13, 14, -1}, /*  12: */
		{-1, -1, 6},  /*  13: (2,-1)  9 bits */
		{15, 16, -1}, /*  14: */
		{-1, -1, 10}, /*  15: (3, 0) 10 bits */
		{17, 36, -1}, /*  16: */
		{18, 19, -1}, /*  17: */
		{-1, -1, 9},  /*  18: (3,-1) 12 bits */
		{20, 29, -1}, /*  19: */
		{21, 26, -1}, /*  20: */
		{22, 25, -1}, /*  21: */
		{23, 24, -1}, /*  22: */
		{-1, -1, 13}, /*  23: (4, 0) 16 bits */
		{-1, -1, 12}, /*  24: (4,-1) 16 bits */
		{-1, -1, 20}, /*  25: (6, 1) 15 bits */
		{27, 28, -1}, /*  26: */
		{-1, -1, 19}, /*  27: (6, 0) 15 bits */
		{-1, -1, 18}, /*  28: (6,-1) 15 bits */
		{30, 33, -1}, /*  29: */
		{31, 32, -1}, /*  30: */
		{-1, -1, 17}, /*  31: (5, 1) 15 bits */
		{-1, -1, 16}, /*  32: (5, 0) 15 bits */
		{34, 35, -1}, /*  33: */
		{-1, -1, 15}, /*  34: (5,-1) 15 bits */
		{-1, -1, 14}, /*  35: (4, 1) 15 bits */
		{-1, -1, 11}, /*  36: (3, 1) 11 bits */
		{-1, -1, 8},  /*  37: (2, 1)  8 bits */
		{-1, -1, 5},  /*  38: (1, 1)  6 bits */
		{-1, -1, 2},  /*  39: (0, 1)  4 bits */
		{-1, -1, 7},  /*  40: (2, 0)  3 bits */
	},
	{ //B3
		{1, 96, -1},  /*   0: */
		{2, 93, -1},  /*   1: */
		{3, 4, -1},   /*   2: */
		{-1, -1, 10}, /*   3: (1, 0)  3 bits */
		{5, 8, -1},   /*   4: */
		{6, 7, -1},   /*   5: */
		{-1, -1, 11}, /*   6: (1, 1)  5 bits */
		{-1, -1, 9},  /*   7: (1,-1)  5 bits */
		{9, 10, -1},  /*   8: */
		{-1, -1, 17}, /*   9: (2, 0)  5 bits */
		{11, 92, -1}, /*  10: */
		{12, 13, -1}, /*  11: */
		{-1, -1, 16}, /*  12: (2,-1)  7 bits */
		{14, 89, -1}, /*  13: */
		{15, 16, -1}, /*  14: */
		{-1, -1, 24}, /*  15: (3, 0)  9 bits */
		{17, 86, -1}, /*  16: */
		{18, 85, -1}, /*  17: */
		{19, 20, -1}, /*  18: */
		{-1, -1, 8},  /*  19: (1,-2) 12 bits */
		{21, 24, -1}, /*  20: */
		{22, 23, -1}, /*  21: */
		{-1, -1, 19}, /*  22: (2, 2) 14 bits */
		{-1, -1, 15}, /*  23: (2,-2) 14 bits */
		{25, 26, -1}, /*  24: */
		{-1, -1, 31}, /*  25: (4, 0) 14 bits */
		{27, 84, -1}, /*  26: */
		{28, 29, -1}, /*  27: */
		{-1, -1, 30}, /*  28: (4,-1) 16 bits */
		{30, 83, -1}, /*  29: */
		{31, 32, -1}, /*  30: */
		{-1, -1, 22}, /*  31: (3,-2) 18 bits */
		{33, 74, -1}, /*  32: */
		{34, 35, -1}, /*  33: */
		{-1, -1, 38}, /*  34: (5, 0) 20 bits */
		{36, 37, -1}, /*  35: */
		{-1, -1, 0},  /*  36: (0,-3) 21 bits */
		{38, 73, -1}, /*  37: */
		{39, 40, -1}, /*  38: */
		{-1, -1, 7},  /*  39: (1,-3) 23 bits */
		{41, 72, -1}, /*  40: */
		{42, 43, -1}, /*  41: */
		{-1, -1, 14}, /*  42: (2,-3) 25 bits */
		{44, 69, -1}, /*  43: */
		{45, 48, -1}, /*  44: */
		{46, 47, -1}, /*  45: */
		{-1, -1, 36}, /*  46: (5,-2) 28 bits */
		{-1, -1, 27}, /*  47: (3, 3) 28 bits */
		{49, 50, -1}, /*  48: */
		{-1, -1, 21}, /*  49: (3,-3) 28 bits */
		{51, 68, -1}, /*  50: */
		{52, 53, -1}, /*  51: */
		{-1, -1, 44}, /*  52: (6,-1) 30 bits */
		{54, 67, -1}, /*  53: */
		{55, 56, -1}, /*  54: */
		{-1, -1, 28}, /*  55: (4,-3) 32 bits */
		{57, 66, -1}, /*  56: */
		{58, 59, -1}, /*  57: */
		{-1, -1, 43}, /*  58: (6,-2) 34 bits */
		{60, 65, -1}, /*  59: */
		{61, 62, -1}, /*  60: */
		{-1, -1, 35}, /*  61: (5,-3) 36 bits */
		{63, 64, -1}, /*  62: */
		{-1, -1, 48}, /*  63: (6, 3) 37 bits */
		{-1, -1, 42}, /*  64: (6,-3) 37 bits */
		{-1, -1, 41}, /*  65: (5, 3) 35 bits */
		{-1, -1, 47}, /*  66: (6, 2) 33 bits */
		{-1, -1, 34}, /*  67: (4, 3) 31 bits */
		{-1, -1, 46}, /*  68: (6, 1) 29 bits */
		{70, 71, -1}, /*  69: */
		{-1, -1, 45}, /*  70: (6, 0) 27 bits */
		{-1, -1, 40}, /*  71: (5, 2) 27 bits */
		{-1, -1, 20}, /*  72: (2, 3) 24 bits */
		{-1, -1, 39}, /*  73: (5, 1) 22 bits */
		{75, 82, -1}, /*  74: */
		{76, 79, -1}, /*  75: */
		{77, 78, -1}, /*  76: */
		{-1, -1, 37}, /*  77: (5,-1) 22 bits */
		{-1, -1, 33}, /*  78: (4, 2) 22 bits */
		{80, 81, -1}, /*  79: */
		{-1, -1, 29}, /*  80: (4,-2) 22 bits */
		{-1, -1, 13}, /*  81: (1, 3) 22 bits */
		{-1, -1, 6},  /*  82: (0, 3) 20 bits */
		{-1, -1, 26}, /*  83: (3, 2) 17 bits */
		{-1, -1, 32}, /*  84: (4, 1) 15 bits */
		{-1, -1, 25}, /*  85: (3, 1) 11 bits */
		{87, 88, -1}, /*  86: */
		{-1, -1, 23}, /*  87: (3,-1) 11 bits */
		{-1, -1, 12}, /*  88: (1, 2) 11 bits */
		{90, 91, -1}, /*  89: */
		{-1, -1, 5},  /*  90: (0, 2)  9 bits */
		{-1, -1, 1},  /*  91: (0,-2)  9 bits */
		{-1, -1, 18}, /*  92: (2, 1)  6 bits */
		{94, 95, -1}, /*  93: */
		{-1, -1, 4},  /*  94: (0, 1)  3 bits */
		{-1, -1, 2},  /*  95: (0,-1)  3 bits */
		{-1, -1, 3},  /*  96: (0, 0)  1 bit  */
	},
	{ //B4
		{1, 26, -1},    /*   0: */
		{2, 5, -1},     /*   1: */
		{3, 4, -1},     /*   2: */
		{-1, -1, 7},    /*   3: (0, 1)  3 bits */
		{-1, -1, 5},    /*   4: (0,-1)  3 bits */
		{6, 23, -1},    /*   5: */
		{7, 22, -1},    /*   6: */
		{8, 11, -1},    /*   7: */
		{9, 10, -1},    /*   8: */
		{-1, -1, 17},   /*   9: (1,-2)  6 bits */
		{-1, -1, 32},   /*  10: (2, 0)  6 bits */
		{12, 21, -1},   /*  11: */
		{13, 18, -1},   /*  12: */
		{14, 15, -1},   /*  13: */
		{-1, -1, 3},    /*  14: (0,-3)  8 bits */
		{16, 17, -1},   /*  15: */
		{-1, -1, 22},   /*  16: (1, 3)  9 bits */
		{-1, -1, 16},   /*  17: (1,-3)  9 bits */
		{19, 20, -1},   /*  18: */
		{-1, -1, 34},   /*  19: (2, 2)  8 bits */
		{-1, -1, 30},   /*  20: (2,-2)  8 bits */
		{-1, -1, 33},   /*  21: (2, 1)  6 bits */
		{-1, -1, 20},   /*  22: (1, 1)  4 bits */
		{24, 25, -1},   /*  23: */
		{-1, -1, 18},   /*  24: (1,-1)  4 bits */
		{-1, -1, 8},    /*  25: (0, 2)  4 bits */
		{27, 28, -1},   /*  26: */
		{-1, -1, 6},    /*  27: (0, 0)  2 bits */
		{29, 30, -1},   /*  28: */
		{-1, -1, 19},   /*  29: (1, 0)  3 bits */
		{31, 32, -1},   /*  30: */
		{-1, -1, 4},    /*  31: (0,-2)  4 bits */
		{33, 180, -1},  /*  32: */
		{34, 35, -1},   /*  33: */
		{-1, -1, 31},   /*  34: (2,-1)  6 bits */
		{36, 179, -1},  /*  35: */
		{37, 42, -1},   /*  36: */
		{38, 41, -1},   /*  37: */
		{39, 40, -1},   /*  38: */
		{-1, -1, 46},   /*  39: (3, 1) 10 bits */
		{-1, -1, 44},   /*  40: (3,-1) 10 bits */
		{-1, -1, 45},   /*  41: (3, 0)  9 bits */
		{43, 166, -1},  /*  42: */
		{44, 47, -1},   /*  43: */
		{45, 46, -1},   /*  44: */
		{-1, -1, 35},   /*  45: (2, 3) 11 bits */
		{-1, -1, 29},   /*  46: (2,-3) 11 bits */
		{48, 165, -1},  /*  47: */
		{49, 164, -1},  /*  48: */
		{50, 161, -1},  /*  49: */
		{51, 156, -1},  /*  50: */
		{52, 155, -1},  /*  51: */
		{53, 70, -1},   /*  52: */
		{54, 69, -1},   /*  53: */
		{55, 60, -1},   /*  54: */
		{56, 57, -1},   /*  55: */
		{-1, -1, 14},   /*  56: (1,-5) 19 bits */
		{58, 59, -1},   /*  57: */
		{-1, -1, 61},   /*  58: (4, 3) 20 bits */
		{-1, -1, 55},   /*  59: (4,-3) 20 bits */
		{61, 68, -1},   /*  60: */
		{62, 65, -1},   /*  61: */
		{63, 64, -1},   /*  62: */
		{-1, -1, 37},   /*  63: (2, 5) 21 bits */
		{-1, -1, 27},   /*  64: (2,-5) 21 bits */
		{66, 67, -1},   /*  65: */
		{-1, -1, 72},   /*  66: (5, 1) 21 bits */
		{-1, -1, 70},   /*  67: (5,-1) 21 bits */
		{-1, -1, 49},   /*  68: (3, 4) 19 bits */
		{-1, -1, 11},   /*  69: (0, 5) 17 bits */
		{71, 72, -1},   /*  70: */
		{-1, -1, 1},    /*  71: (0,-5) 17 bits */
		{73, 154, -1},  /*  72: */
		{74, 75, -1},   /*  73: */
		{-1, -1, 41},   /*  74: (3,-4) 19 bits */
		{76, 77, -1},   /*  75: */
		{-1, -1, 71},   /*  76: (5, 0) 20 bits */
		{78, 151, -1},  /*  77: */
		{79, 142, -1},  /*  78: */
		{80, 83, -1},   /*  79: */
		{81, 82, -1},   /*  80: */
		{-1, -1, 62},   /*  81: (4, 4) 24 bits */
		{-1, -1, 54},   /*  82: (4,-4) 24 bits */
		{84, 141, -1},  /*  83: */
		{85, 88, -1},   /*  84: */
		{86, 87, -1},   /*  85: */
		{-1, -1, 74},   /*  86: (5, 3) 26 bits */
		{-1, -1, 68},   /*  87: (5,-3) 26 bits */
		{89, 102, -1},  /*  88: */
		{90, 97, -1},   /*  89: */
		{91, 92, -1},   /*  90: */
		{-1, -1, 26},   /*  91: (2,-6) 28 bits */
		{93, 94, -1},   /*  92: */
		{-1, -1, 83},   /*  93: (6,-1) 29 bits */
		{95, 96, -1},   /*  94: */
		{-1, -1, 75},   /*  95: (5, 4) 30 bits */
		{-1, -1, 67},   /*  96: (5,-4) 30 bits */
		{98, 99, -1},   /*  97: */
		{-1, -1, 84},   /*  98: (6, 0) 28 bits */
		{100, 101, -1}, /*  99: */
		{-1, -1, 63},   /* 100: (4, 5) 29 bits */
		{-1, -1, 53},   /* 101: (4,-5) 29 bits */
		{103, 140, -1}, /* 102: */
		{104, 139, -1}, /* 103: */
		{105, 108, -1}, /* 104: */
		{106, 107, -1}, /* 105: */
		{-1, -1, 86},   /* 106: (6, 2) 30 bits */
		{-1, -1, 82},   /* 107: (6,-2) 30 bits */
		{109, 138, -1}, /* 108: */
		{110, 111, -1}, /* 109: */
		{-1, -1, 39},   /* 110: (3,-6) 31 bits */
		{112, 137, -1}, /* 111: */
		{113, 114, -1}, /* 112: */
		{-1, -1, 81},   /* 113: (6,-3) 33 bits */
		{115, 134, -1}, /* 114: */
		{116, 133, -1}, /* 115: */
		{117, 118, -1}, /* 116: */
		{-1, -1, 52},   /* 117: (4,-6) 36 bits */
		{119, 132, -1}, /* 118: */
		{120, 121, -1}, /* 119: */
		{-1, -1, 80},   /* 120: (6,-4) 38 bits */
		{122, 125, -1}, /* 121: */
		{123, 124, -1}, /* 122: */
		{-1, -1, 77},   /* 123: (5, 6) 40 bits */
		{-1, -1, 65},   /* 124: (5,-6) 40 bits */
		{126, 131, -1}, /* 125: */
		{127, 128, -1}, /* 126: */
		{-1, -1, 79},   /* 127: (6,-5) 41 bits */
		{129, 130, -1}, /* 128: */
		{-1, -1, 90},   /* 129: (6, 6) 42 bits */
		{-1, -1, 78},   /* 130: (6,-6) 42 bits */
		{-1, -1, 89},   /* 131: (6, 5) 40 bits */
		{-1, -1, 88},   /* 132: (6, 4) 37 bits */
		{-1, -1, 76},   /* 133: (5, 5) 35 bits */
		{135, 136, -1}, /* 134: */
		{-1, -1, 66},   /* 135: (5,-5) 35 bits */
		{-1, -1, 64},   /* 136: (4, 6) 35 bits */
		{-1, -1, 87},   /* 137: (6, 3) 32 bits */
		{-1, -1, 51},   /* 138: (3, 6) 30 bits */
		{-1, -1, 85},   /* 139: (6, 1) 28 bits */
		{-1, -1, 38},   /* 140: (2, 6) 27 bits */
		{-1, -1, 12},   /* 141: (0, 6) 24 bits */
		{143, 148, -1}, /* 142: */
		{144, 145, -1}, /* 143: */
		{-1, -1, 0},    /* 144: (0,-6) 24 bits */
		{146, 147, -1}, /* 145: */
		{-1, -1, 25},   /* 146: (1, 6) 25 bits */
		{-1, -1, 13},   /* 147: (1,-6) 25 bits */
		{149, 150, -1}, /* 148: */
		{-1, -1, 50},   /* 149: (3, 5) 24 bits */
		{-1, -1, 40},   /* 150: (3,-5) 24 bits */
		{152, 153, -1}, /* 151: */
		{-1, -1, 73},   /* 152: (5, 2) 22 bits */
		{-1, -1, 69},   /* 153: (5,-2) 22 bits */
		{-1, -1, 24},   /* 154: (1, 5) 18 bits */
		{-1, -1, 36},   /* 155: (2, 4) 15 bits */
		{157, 158, -1}, /* 156: */
		{-1, -1, 28},   /* 157: (2,-4) 15 bits */
		{159, 160, -1}, /* 158: */
		{-1, -1, 60},   /* 159: (4, 2) 16 bits */
		{-1, -1, 56},   /* 160: (4,-2) 16 bits */
		{162, 163, -1}, /* 161: */
		{-1, -1, 48},   /* 162: (3, 3) 14 bits */
		{-1, -1, 42},   /* 163: (3,-3) 14 bits */
		{-1, -1, 23},   /* 164: (1, 4) 12 bits */
		{-1, -1, 47},   /* 165: (3, 2) 11 bits */
		{167, 170, -1}, /* 166: */
		{168, 169, -1}, /* 167: */
		{-1, -1, 43},   /* 168: (3,-2) 11 bits */
		{-1, -1, 10},   /* 169: (0, 4) 11 bits */
		{171, 172, -1}, /* 170: */
		{-1, -1, 2},    /* 171: (0,-4) 11 bits */
		{173, 174, -1}, /* 172: */
		{-1, -1, 15},   /* 173: (1,-4) 12 bits */
		{175, 178, -1}, /* 174: */
		{176, 177, -1}, /* 175: */
		{-1, -1, 59},   /* 176: (4, 1) 14 bits */
		{-1, -1, 57},   /* 177: (4,-1) 14 bits */
		{-1, -1, 58},   /* 178: (4, 0) 13 bits */
		{-1, -1, 9},    /* 179: (0, 3)  7 bits */
		{-1, -1, 21},   /* 180: (1, 2)  5 bits */

	},
}
