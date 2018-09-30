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

/*Kind is  Names for the five varieties of bliss-b */
type Kind byte

/*Names for the five varieties of bliss-b */
const (
	B0 Kind = iota
	B1
	B2
	B3
	B4
)

//ParamT is a param for each BlissB0~B4
type ParamT struct {
	kind  Kind  /* the kind of bliss-b (i.e. *this* choice of parameters)  */
	q     int32 /* field modulus  */
	qBits uint
	n     int /* ring size (x^n+1)  */
	nBits uint
	d     uint32 /* bit drop shift  */
	modP  int32  /* magic modulus  (derived from d) */
	q2    int32  /* 2 * field modulus  */
	qInv  int32  /* floor(2^32/q)      */
	q2Inv int32  /* floor(2^32/q2)     */
	oneQ2 int32  /* 1/(q+2) mod 2q     */
	kappa uint32 /* index vector size  */

	bInf  uint32 /* infinite norm  */
	bBits uint
	bL2   uint32 /* L2 norm  */

	nz1 uint32 /* nonzero +-1  aka delta_1*n in L Ducas' Bliss-B paper */
	nz2 uint32 /* nonzero +-2  aka delta_2*n  in L Ducas' Bliss-B paper */

	sigma uint32 /* standard deviation  */

	bigM uint32 /*  We use P_{max} given on page 7 of L Ducas' Bliss-B  paper */

	m float64 /* repetition rate  */

	/*
	 * Tables for the NTT transform
	 */

	w []int32 /* n roots of unity (mod q)  */
	r []int32 /* w[i]/n (mod q)  */
	/*
	 * parameters used by the sampler (in addition to sigma)
	 */
	ell       uint32 /* number of rows in table for Gaussian sampling */
	precision uint32 /* 8 * number of columns in the table */
}

/*
 * Why we use M = p_max (by Tancrede)
 *
 *
 *
 * Let's go:
 *
 * It should always hold that p->M >= norm_v in order to ensure that
 * 1/(M*exp(-||v||^2/(2*sigma^2))) <= 1
 *
 * BLISS-B states that ||v||^2 < P_max, where P_max is given on p.7
 *
 * *** Therefore you see here that you need p->M = P_max. ***
 *
 *
 * Let's take BLISS-B1
 * P_max = 17825
 * Which makes exp(-17825/(2*215^2)) = 0.6800330729375813
 * and a repetition rate m that needs to verify m >= 1.21264863594269231
 * which yields alpha = sqrt(1/(2*log(m))) = 1.610362655
 *
 * The values M and alpha from BLISS-B are actually not parameters,
 * they are approximate values to understand what is going on.
 *
 * If you had taken alpha=1.610, we would have
 * exp(1/(2*1.61*1.61)) = 1.2127539833
 * and if we compute p->M as you did, it now yields
 * p->M = ((2*sigma^2)/(2*alpha^2)) = (sigma/alpha)^2 = 17833.031 (we need to take the ceil)
 * (this is where BLISS-B error in the paper is:
 * alpha = sigma / sqrt(P_max)) and not alpha = sigma/P_max)
 *
 *
 *
 * Anyway, the *real* value one should be taking for p->M is P_max
 * computed as in BLISS-B p.7
 *
 */

/*
 * Roots of unity. q = 7681  n = 256
 * w is a primitive root of unity (i.e. w^n mod q = 1)
 * psi is the square root of w  (i.e. a 2n primitive root
 * of unity (i.i.e  psi^2n mod q = 1))
 * in this table w = 2028 and psi = 7146
 * and this table is [psi^0, psi^1, psi^2, ...  psi^(n - 1)]
 *
 * These tables are generated by tools/blzzd_tables.c
 */
var w7681n256 = []int32{
	1, 7146, 2028, 5722, 3449, 5906, 4862, 2689,
	5413, 7463, 1415, 3394, 4607, 856, 2900, 62,
	5235, 2840, 1438, 6451, 5165, 1885, 5417, 5323,
	1846, 3239, 3041, 1437, 6986, 3137, 3844, 1968,
	7098, 4665, 550, 5309, 1655, 5571, 7424, 6918,
	1112, 4198, 4603, 2996, 2469, 217, 6801, 2259,
	5033, 3376, 6556, 2757, 7438, 7109, 6461, 7496,
	6803, 1189, 1408, 7139, 5773, 6888, 1800, 4806,
	1925, 7060, 1952, 296, 2941, 1170, 3892, 7012,
	4589, 2805, 4801, 4600, 4601, 4066, 6094, 4135,
	7584, 5809, 2990, 5679, 3411, 3193, 4608, 321,
	4928, 5784, 1003, 1065, 6300, 1459, 2897, 1667,
	6832, 1036, 6453, 4095, 5941, 1499, 4540, 5977,
	5282, 738, 4582, 6550, 5967, 2951, 3501, 1129,
	2784, 674, 417, 7335, 766, 4964, 1886, 4882,
	7351, 7568, 6688, 1266, 6299, 1994, 869, 3626,
	3383, 2811, 1591, 1406, 528, 1717, 3125, 2583,
	675, 7563, 1682, 6488, 732, 111, 2063, 2359,
	5300, 6470, 2681, 2012, 6601, 1725, 6526, 3445,
	365, 4431, 2844, 6979, 6882, 5010, 319, 5998,
	1728, 4921, 1848, 2169, 7097, 5200, 6203, 7268,
	5887, 7346, 2562, 4229, 3380, 4416, 3188, 7283,
	5543, 7042, 3901, 2197, 7479, 536, 5118, 3987,
	2273, 5224, 1044, 2173, 4957, 5631, 6048, 5702,
	6468, 3751, 5637, 2838, 2508, 2395, 1402, 2668,
	1286, 3280, 4149, 94, 3477, 6288, 198, 1604,
	2132, 3849, 6974, 1876, 2551, 2433, 4115, 2922,
	3654, 3765, 5828, 506, 5806, 4595, 7276, 1607,
	527, 2252, 1097, 4542, 4907, 1657, 4501, 3799,
	3000, 329, 648, 6646, 693, 5614, 7462, 1950,
	1366, 6566, 5088, 4675, 2881, 2546, 5108, 1656,
	5036, 1771, 4959, 4561, 2423, 1784, 5685, 201,
}

/*
* iam: this table is [- (psi^0)/n, - (psi^1)/n, - (psi^2)/n, ...  - (psi^(n - 1))/n]
* but we are not sure why there is a minus here.
*
* BD: got it. That's because the code does not use an inverse nnt,
* but applies the same ntt twice. The multiplication starts with
*
*     c = ntt(ntt(a * w) * ntt(b * w))
*
* instead of this
*
*     d = inv_ntt(ntt(a * w) * ntt(b * w)),
*
* where '*' means elementwise multiplication. The coefficients of c are
* the same as in d but in a different order:
*
*  c[0] = d[0]
*  c[i] = d[n - i]  for i=1 to n-1
*
* To get the final result, we must multiply d[i] by 1/n * 1/psi^i.
* To get the same thing in c, we multiply c[i] by 1/n * 1/psi^(n - i).
* That's what the table r is about:
*
*   r[i] = 1/n * 1/psi^(n - i)
*        = 1/n * psi^i * 1/psi^n
*        = - (psi^i)/n            because psi^n = -1.
*
* Then the code applies a permutation to c to put the coefficients in
* the right order. There's a slight inefficiency since multiplying c[0]
* by r[0] gives the opposite of what we want (wrong sign). This gets
* adjusted too in the permutation code.
*
* These tables are generated by tools/blzzd_tables.c
 */
var r7681n256 = []int32{
	30, 6993, 7073, 2678, 3617, 517, 7602, 3860,
	1089, 1141, 4045, 1967, 7633, 2637, 2509, 1860,
	3430, 709, 4735, 1505, 1330, 2783, 1209, 6070,
	1613, 4998, 6739, 4705, 2193, 1938, 105, 5273,
	5553, 1692, 1138, 5650, 3564, 5829, 7652, 153,
	2636, 3044, 7513, 5389, 4941, 6510, 4324, 6322,
	5051, 1427, 4655, 5900, 391, 5883, 1805, 2131,
	4384, 4946, 3835, 6783, 4208, 6934, 233, 5922,
	3983, 4413, 4793, 1199, 3739, 4376, 1545, 2973,
	7093, 7340, 5772, 7423, 7453, 6765, 6157, 1154,
	4771, 5288, 5209, 1388, 2477, 3618, 7663, 1949,
	1901, 4538, 7047, 1226, 4656, 5365, 2419, 3924,
	5254, 356, 1565, 7635, 1567, 6565, 5623, 2647,
	4840, 6778, 6883, 4475, 2347, 4039, 5177, 3146,
	6710, 4858, 4829, 4982, 7618, 2981, 2813, 521,
	5462, 4291, 934, 7256, 4626, 6053, 3027, 1246,
	1637, 7520, 1644, 3775, 478, 5424, 1578, 680,
	4888, 4141, 4374, 2615, 6598, 3330, 442, 1641,
	5380, 2075, 3620, 6593, 6005, 5664, 3755, 3497,
	3269, 2353, 829, 1983, 6754, 4361, 1889, 3277,
	5754, 1691, 1673, 3622, 5523, 2380, 1746, 2972,
	7628, 5312, 50, 3974, 1547, 1903, 3468, 3422,
	4989, 3873, 1815, 4462, 1621, 718, 7601, 4395,
	6742, 3100, 596, 3742, 2771, 7629, 4777, 2078,
	2015, 4996, 128, 649, 6111, 2721, 3655, 3230,
	175, 6228, 1574, 2820, 4457, 4296, 5940, 2034,
	2512, 255, 1833, 2513, 7401, 3861, 554, 3169,
	2086, 5416, 5858, 7499, 5198, 7273, 3212, 2124,
	448, 6112, 2186, 5683, 1271, 3624, 4453, 6436,
	5509, 2189, 4078, 7355, 5428, 7119, 1111, 4733,
	2575, 4955, 6701, 1992, 1939, 7251, 7301, 3594,
	5141, 7044, 2831, 6253, 3561, 7434, 1568, 6030,
}

/*
* These tables are generated by tools/blzzd_tables.c
 */
var w12289n512 = []int32{
	1, 10302, 3400, 3150, 8340, 6281, 5277, 9407,
	12149, 7822, 3271, 1404, 12144, 5468, 10849, 10232,
	7311, 10930, 9042, 64, 8011, 8687, 4976, 5333,
	8736, 5925, 12176, 3329, 9048, 431, 3833, 3009,
	5860, 6152, 3531, 922, 11336, 1105, 4096, 8855,
	2963, 11239, 9509, 6099, 10530, 5057, 4143, 1489,
	3006, 11821, 8241, 6370, 480, 4782, 9852, 453,
	9275, 4075, 1426, 5297, 6534, 6415, 9377, 10314,
	4134, 7083, 9273, 8049, 6915, 11286, 2143, 6142,
	11112, 3789, 4414, 3728, 2731, 5241, 7205, 350,
	5023, 10256, 8779, 6507, 10908, 3600, 11287, 156,
	9542, 1973, 12129, 10695, 9005, 12138, 5101, 2738,
	3621, 6427, 10111, 1958, 5067, 8851, 10911, 9928,
	9198, 9606, 9984, 8527, 3382, 2049, 8585, 11026,
	2625, 6950, 3186, 10542, 5791, 8076, 2422, 4774,
	1170, 10120, 8653, 11089, 334, 12237, 5012, 7535,
	8246, 8724, 5191, 8243, 2396, 7280, 11082, 1954,
	726, 7540, 10600, 1146, 8652, 787, 9223, 9087,
	8961, 1254, 2969, 11606, 5331, 421, 11414, 5876,
	11227, 8775, 2166, 9597, 3289, 2505, 11899, 723,
	1212, 400, 3985, 8210, 6522, 5681, 5444, 9381,
	2366, 5445, 7394, 5766, 8595, 3445, 12047, 1583,
	563, 11907, 9405, 3834, 1022, 9260, 9302, 11871,
	7203, 4324, 10512, 3956, 4388, 6234, 354, 9364,
	11567, 9090, 3000, 11454, 130, 12048, 11885, 3963,
	2768, 5456, 10115, 6299, 6378, 9162, 7404, 10474,
	5728, 10367, 9424, 2948, 4177, 7665, 8005, 8320,
	9154, 11011, 7852, 5106, 5092, 8332, 9888, 2655,
	8785, 6874, 6730, 10211, 12171, 975, 4337, 9259,
	11289, 8471, 4053, 8273, 4231, 10968, 7270, 6374,
	4821, 6093, 10163, 9235, 9821, 605, 2187, 4737,
	955, 7210, 2704, 9734, 1428, 1323, 1045, 426,
	1479, 10587, 2399, 1319, 8993, 11404, 1168, 1805,
	1853, 4789, 8232, 11964, 6747, 1010, 8526, 5369,
	10938, 5435, 2686, 8633, 1673, 6068, 10682, 10258,
	4805, 1018, 4919, 7991, 11560, 10710, 3778, 1693,
	3195, 4948, 11813, 11848, 3748, 12147, 11796, 8760,
	7393, 7753, 5195, 295, 3707, 7591, 7575, 2500,
	9545, 8301, 10040, 7856, 9447, 6403, 8643, 6381,
	3201, 5315, 7635, 6170, 4632, 677, 6591, 3757,
	6553, 5529, 243, 8719, 2837, 3532, 11224, 2447,
	4255, 147, 2847, 8240, 8357, 9369, 1632, 1512,
	6461, 3998, 6957, 1566, 9764, 3263, 5011, 9522,
	4846, 5574, 9140, 1962, 9408, 10162, 11222, 6421,
	9744, 6136, 10745, 7967, 10092, 2844, 1912, 10446,
	12208, 1190, 7247, 2919, 355, 7377, 2678, 12240,
	11340, 5446, 5407, 9166, 11745, 11785, 6039, 6860,
	9970, 11767, 4938, 7105, 2426, 9115, 2481, 10431,
	5146, 11635, 9153, 709, 4452, 1956, 9041, 2051,
	4611, 5537, 8925, 11341, 3459, 8807, 27, 7796,
	5777, 11316, 3978, 9830, 7300, 8209, 8509, 2281,
	2294, 1041, 8374, 168, 10276, 5906, 773, 174,
	10643, 1728, 7384, 1058, 11462, 8812, 2381, 218,
	9238, 3860, 10805, 11637, 5179, 7509, 10752, 6347,
	9314, 316, 11136, 5257, 12280, 5594, 6267, 8517,
	10963, 4916, 1663, 1360, 1260, 3336, 7428, 11942,
	1305, 12233, 671, 6224, 7935, 12231, 4645, 11713,
	1635, 7840, 4372, 1159, 7399, 8120, 1017, 6906,
	4591, 8410, 2370, 9786, 8705, 6077, 5088, 3991,
	8577, 2344, 3, 6328, 10200, 9450, 442, 6554,
	3542, 3643, 11869, 11177, 9813, 4212, 11854, 4115,
	7969, 6118, 9644, 8212, 2548, 192, 11744, 1483,
	2639, 3710, 1630, 5486, 11950, 9987, 2566, 1293,
	11499, 9027, 5291, 6167, 10593, 2766, 9430, 3315,
}

/*
* These tables are generated by tools/blzzd_tables.c
 */
var r12289n512 = []int32{
	24, 1468, 7866, 1866, 3536, 3276, 3758, 4566,
	8929, 3393, 4770, 9118, 8809, 8342, 2307, 12077,
	3418, 4251, 8095, 1536, 7929, 11864, 8823, 5102,
	751, 7021, 9577, 6162, 8239, 10344, 5969, 10771,
	5461, 180, 11010, 9839, 1706, 1942, 12281, 3607,
	9667, 11667, 7014, 11197, 6940, 10767, 1120, 11158,
	10699, 1057, 1160, 5412, 11520, 4167, 2957, 10872,
	1398, 11777, 9646, 4238, 9348, 6492, 3846, 1756,
	904, 10235, 1350, 8841, 6203, 506, 2276, 12229,
	8619, 4913, 7624, 3449, 4099, 2894, 874, 8400,
	9951, 364, 1783, 8700, 3723, 377, 530, 3744,
	7806, 10485, 8449, 10900, 7207, 8665, 11823, 4267,
	881, 6780, 9173, 10125, 11007, 3511, 3795, 4781,
	11839, 9342, 6125, 8024, 7434, 20, 9416, 6555,
	1555, 7043, 2730, 7228, 3805, 9489, 8972, 3975,
	3502, 9389, 11048, 8067, 8016, 11041, 9687, 8794,
	1280, 463, 1694, 1208, 8348, 2674, 7899, 10029,
	5135, 8914, 8620, 2926, 11024, 6599, 150, 9175,
	6151, 5518, 9811, 8186, 5054, 10104, 3578, 5845,
	11379, 1687, 2828, 9126, 5202, 10964, 2929, 5063,
	4510, 9600, 9617, 416, 9060, 1165, 7766, 3942,
	7628, 7790, 5410, 3205, 9656, 8946, 6481, 1125,
	1223, 3121, 4518, 5993, 12239, 1038, 2046, 2257,
	826, 5464, 6508, 8921, 7000, 2148, 8496, 3534,
	7250, 9247, 10555, 4538, 3120, 6505, 2593, 9089,
	4987, 8054, 9269, 3708, 5604, 10975, 5650, 5596,
	2293, 3028, 4974, 9307, 1936, 11914, 7785, 3056,
	10783, 6195, 4113, 11943, 11607, 3344, 3821, 2275,
	1927, 5219, 1763, 11573, 9457, 11111, 5776, 1014,
	578, 6680, 11249, 1928, 3232, 5163, 2434, 5508,
	5103, 11053, 10421, 438, 2213, 2231, 3332, 3087,
	10631, 994, 3451, 125, 9694, 7174, 502, 10224,
	10918, 8308, 8420, 7078, 6919, 3338, 3454, 6453,
	7605, 4335, 944, 4489, 2171, 11951, 8000, 5966,
	4443, 7550, 3019, 10568, 3285, 10453, 10588, 412,
	4719, 12143, 7455, 7449, 7082, 11260, 4649, 3765,
	2946, 8151, 865, 1705, 3929, 8881, 457, 1327,
	5386, 1737, 1790, 7080, 2945, 10138, 9754, 10844,
	7878, 2600, 7469, 4209, 5526, 6204, 10808, 5676,
	3090, 4670, 11194, 612, 567, 3959, 10716, 4145,
	9804, 9806, 5832, 343, 6643, 11034, 11307, 9572,
	3808, 3528, 6883, 1136, 3944, 3654, 2301, 11710,
	7596, 9929, 7211, 717, 845, 4578, 9663, 7326,
	5703, 10886, 10447, 10221, 4590, 10397, 11259, 6636,
	365, 12085, 12100, 6873, 8717, 6811, 9021, 4924,
	10345, 3982, 1882, 8611, 8520, 5002, 2827, 11113,
	1802, 7814, 6878, 11071, 11522, 193, 9757, 4883,
	5789, 12050, 7911, 10763, 9068, 9847, 10388, 4564,
	614, 8882, 10759, 4727, 8536, 10077, 8071, 68,
	63, 9998, 5287, 1826, 9282, 2455, 648, 2769,
	3469, 1226, 9449, 2429, 3154, 392, 7592, 5588,
	5900, 406, 4352, 4032, 844, 6565, 6263, 4176,
	9652, 4605, 5170, 814, 4730, 2575, 7988, 5232,
	510, 6617, 1251, 8930, 1406, 8170, 12268, 4860,
	2334, 7584, 9195, 3278, 12073, 11366, 2940, 7784,
	5043, 7383, 3045, 8062, 5662, 6330, 6226, 3961,
	6742, 10945, 3815, 1908, 6105, 10897, 879, 10754,
	2373, 3825, 6616, 3238, 5530, 10545, 12119, 5987,
	11872, 5216, 7724, 1373, 7, 10669, 11511, 9761,
	9224, 7100, 72, 4404, 11309, 5598, 10608, 9828,
	11274, 1409, 2209, 10179, 2021, 2776, 1849, 448,
	6921, 11653, 10254, 464, 11996, 4608, 11498, 11014,
	1891, 3017, 2253, 8774, 4153, 6197, 139, 6454,
	5618, 7735, 4094, 540, 8452, 4939, 5118, 5826,
}

var blissBParams = []*ParamT{

	/* bliss-b 0 */
	&ParamT{
		kind:      B0,   /* kind */
		q:         7681, /* q */
		qBits:     13,
		n:         256, /* n */
		nBits:     8,
		d:         5,      /* d */
		modP:      480,    /* mod_p */
		q2:        15362,  /* 2 * field modulus  */
		qInv:      559167, /* floor(2^32/q)      */
		q2Inv:     279583, /* floor(2^32/q2)     */
		oneQ2:     3841,   /* 1/(q + 2) mod 2q   */
		kappa:     12,     /* kappa */
		bInf:      530,    /* b_inf */
		bBits:     10 + 1,
		bL2:       2492 * 2492, /* L2 norm */
		nz1:       141,         /* nz1 */
		nz2:       39,          /* nz2 */
		sigma:     100,         /* sigma */
		bigM:      17928,       /* M  (actually p_max. see workings below) */
		m:         2.44,        /* m  = repetition rate alpha 0.748   M = 17840  */
		w:         w7681n256,   /* w */
		r:         r7681n256,   /* r */
		ell:       19,          /* ell (computed by tools/ell) */
		precision: 64,          /* precision */
	},

	/* bliss-b 1 */
	&ParamT{
		kind:      B1,    /* kind */
		q:         12289, /* q */
		qBits:     14,
		n:         512, /* n */
		nBits:     9,
		d:         10,     /* d */
		modP:      24,     /* mod_p */
		q2:        24578,  /* q2 = 2 * field modulus  */
		qInv:      349496, /* q_inv = floor(2^32/q) */
		q2Inv:     174748, /* q2_inv = floor(2^32/q2) */
		oneQ2:     6145,   /* one_q2 = 1/(q + 2) mod 2q */
		kappa:     23,     /* kappa */
		bInf:      2100,   /* b_inf */
		bBits:     12 + 1,
		bL2:       12872 * 12872, /* b_l2 = square of L2 norm */
		nz1:       154,           /* nz1 = number of coeffs equal to +/-1 in the private key */
		nz2:       0,             /* nz2 = number of coeffs equal to +/-2 */
		sigma:     215,           /* sigma */
		bigM:      17825,         /* M  (actually p_max. see workings below)  */
		m:         1.21,          /* m = repetition rate BLISS  strongswan .M = 46539, with alpha = 1.000. BLISS-B .M = 17954, with alpha = 1.610 (we get 17623) */
		w:         w12289n512,    /* w = powers of omega  (for NTT) */
		r:         r12289n512,    /* r = powers of omeag/n (for inverse NTT) */
		ell:       21,            /* ell */
		precision: 64,            /* precision */
	},

	/* bliss-b 2 */

	&ParamT{
		kind:      B2,    /* kind */
		q:         12289, /* q */
		qBits:     14,
		n:         512, /* n */
		nBits:     9,
		d:         10,     /* d */
		modP:      24,     /* mod_p */
		q2:        24578,  /* 2 * field modulus  */
		qInv:      349496, /* floor(2^32/q)      */
		q2Inv:     174748, /* floor(2^32/q2)     */
		oneQ2:     6145,   /* 1/(q + 2) mod 2q   */
		kappa:     23,     /* kappa */
		bInf:      1563,   /* b_inf */
		bBits:     11 + 1,
		bL2:       11074 * 11074, /* L2 norm */
		nz1:       154,           /* nz1 */
		nz2:       0,             /* nz2 */
		sigma:     107,           /* sigma */
		bigM:      17825,         /* M (actually p_max. see workings below) */
		m:         2.18,          /* m  = repetition rate  alpha = 0.801 */
		w:         w12289n512,    /* w */
		r:         r12289n512,    /* r */
		ell:       19,            /* ell: computed by tools/ell.c */
		precision: 64,            /* precision */
	},

	/* bliss-b 3 */

	&ParamT{
		kind:      B3,    /* kind */
		q:         12289, /* q */
		qBits:     14,
		n:         512, /* n */
		nBits:     9,
		d:         9,      /* d */
		modP:      48,     /* mod_p */
		q2:        24578,  /* 2 * field modulus  */
		qInv:      349496, /* floor(2^32/q)      */
		q2Inv:     174748, /* floor(2^32/q2)     */
		oneQ2:     6145,   /* 1/(q + 2) mod 2q   */
		kappa:     30,     /* kappa */
		bInf:      1760,   /* b_inf */
		bBits:     11 + 1,
		bL2:       10206 * 10206, /* L2 norm */
		nz1:       216,           /* nz1 */
		nz2:       16,            /* nz2 */
		sigma:     250,           /* sigma */
		bigM:      42270,         /* M  (actually p_max. see workings below) */
		m:         1.40,          /* m  = repetition rate strongswan BLISS .M = 128113,  with alpha = 0.700. BLISS_B .M = 42455, with alpha = 1.216 (we get 42059) */
		w:         w12289n512,    /* w */
		r:         r12289n512,    /* r */
		ell:       21,            /* ell */
		precision: 64,            /* precision */
	},

	/* bliss-b 4 */

	&ParamT{
		kind:      B4,    /* kind */
		q:         12289, /* q */
		qBits:     14,
		n:         512,    /* n */
		nBits:     9,      /* n */
		d:         8,      /* d */
		modP:      96,     /* mod_p */
		q2:        24578,  /* 2 * field modulus  */
		qInv:      349496, /* floor(2^32/q)      */
		q2Inv:     174748, /* floor(2^32/q2)     */
		oneQ2:     6145,   /* 1/(q + 2) mod 2q   */
		kappa:     39,     /* kappa */
		bInf:      1613,   /* b_inf */
		bBits:     11 + 1,
		bL2:       9901 * 9901, /* L2 norm */
		nz1:       231,         /* nz1 */
		nz2:       31,          /* nz2 */
		sigma:     271,         /* sigma */
		bigM:      69576,       /* M (actually p_max. see workings below) */
		m:         1.61,        /* m  = repetition rate strongswan .M = 244186,  with alpha = 0.550  BLISS-B .M = 70034,  with alpha = 1.027  (we get 69950) */
		w:         w12289n512,  /* w */
		r:         r12289n512,  /* r */
		ell:       22,          /* ell */
		precision: 64,          /* precision */
	},
}

//GetParam get a param of kind.
func GetParam(kind Kind) (*ParamT, error) {
	if B0 <= kind && kind <= B4 {
		return blissBParams[kind], nil
	}
	return nil, errors.New("invalid bliss kind")
}

//PKSize returns the size of publickey.
func (p *ParamT) PKSize() int {
	return int(p.qBits)*p.n/8 + 1
}

//SigSize returns the size of signature..
func (p *ParamT) SigSize() int {
	nbits := (int(p.bBits)*p.n + int(p.z2bits())*p.n + int(p.kappa)*int(p.nBits)) + 3
	//z1+z2+c+kind
	if nbits&0x7 == 0 {
		return nbits/8 + 1
	}
	return nbits/8 + 1 + 1
}
func (p *ParamT) z2bits() uint {
	return uint(p.bBits) - uint(p.d)
}