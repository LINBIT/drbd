/*
   erasure_code_gf16.c

   Copyright (C) 2018, Bernhard Oemer, AIT Austrian Institute of Technology GmbH

   Integrated into DRBD by Joel Colledge, LINBIT Information Technologies GmbH
 */

#include <linux/compiler.h>
#include <linux/types.h>
#include <linux/string.h>
#include <linux/bug.h>

/* TODO: Non-portable, only include this in variant for x86 with AVX enabled */
#include <asm/fpu/api.h>

#include "erasure_code_gf16.h"

typedef unsigned char gf_t;
typedef long long word_t  __attribute__ ((__vector_size__ (32)));

#define GF_M 4
#define GF_Q (1 << GF_M)

#define NMAX GF_Q
#define RMAX (NMAX / 2)

#define BS 4096

#define SS (BS / GF_M)
#define WS sizeof(word_t)
#define SLEN (SS / WS)

typedef word_t slice_t[SLEN];
typedef slice_t block_t[GF_M];

#define gfmul(x, y) gf_exp[gf_log[x] + gf_log[y]]
#define gfdiv(x, y) gf_exp[GF_Q - 1 + gf_log[x] - gf_log[y]]
#define gflog(x)    gf_log[x]

const int gf_rpoly[9] = {0, 0, 0x03, 0x0b, 0x13, 0x25, 0x43, 0x89, 0x11d};

short gf_log[GF_Q];
gf_t gf_exp[4 * GF_Q];
short gf_weight[GF_Q];

static inline gf_t gfexp(int x)
{
	x = (x & (GF_Q - 1)) + (x >> GF_M);
	return gf_exp[x];
}

static inline int next_choose(int x)
{
	int c = x & -x, r = x + c;
	return ((r ^ x) >> (2 + __builtin_ctz(x))) | r;
}

static void gf_init(void)
{
	unsigned x = 1, i = 0, r = gf_rpoly[GF_M];

	for (i = 0; i < GF_Q - 1; ++i) {
		gf_exp[i] = x;
		gf_log[x] = i;
		x <<= 1;
		if (x & GF_Q)
			x ^= r;
	}

	gf_log[0] = 2 * GF_Q;

	for (; i < 2 * GF_Q; ++i)
		gf_exp[i] = gf_exp[i % (GF_Q - 1)];

	for (; i < 4 * GF_Q; ++i)
		gf_exp[i] = 0;

	gf_weight[0] = 0;

	for (i = 1; i < GF_Q; ++i) {
		int w = 0, l = gflog(i), j;

		for (j = 0; j < GF_M; ++j)
			w += __builtin_popcount(gf_exp[l + j]);

		gf_weight[i] = w;
	}
}

static int gf_solve(gf_t *v, int n, int k)
{
	int i, j, l;
	gf_t c;

	for (l = 0; l < k; ++l) {
		c = v[l * n + l];
		if (!c) {
			for (i = l + 1; i < k; ++i) {
				c = v[i * n + l];
				if (c)
					break;
			}

			if (i >= k)
				return 1;        /* matrix is singular */

			for (j = l; j < n; ++j)
				v[l * n + j] ^= v[i * n + j];
		}

		if (c != 1) {
			v[l * n + l] = 1;

			for (j = l + 1; j < n; ++j)
				v[l * n + j] = gfdiv(v[l * n + j], c);
		}

		for (i = 0; i < k; ++i) {
			if (i == l)
				continue;

			c = v[i * n + l];

			if (!c)
				continue;

			v[i * n + l] = 0;

			if (c == 1) {
				for (j = l + 1; j < n; ++j)
					v[i * n + j] ^= v[l * n + j];
			} else {
				for (j = l + 1; j < n; ++j)
					v[i * n + j] ^= gfmul(v[l * n + j], c);
			}
		}
	}

	return 0;
}

static void gf_xvandermonde(gf_t *v, int n, int k)
{
	int i, j;
	BUG_ON(k > n || n > GF_Q);

	for (i = 0; i < k; ++i) {
		for (j = 0; j < k - 1; ++j)
			v[i * n + j] = gfexp(i * j);

		v[i * n + j++] = (i == k - 1);

		for (; j < n; ++j)
			v[i * n + j] = gfexp(i * (j - 1));
	}

	gf_solve(v, n, k);
}

static int gf_minweight_par(gf_t *v, int n, int k, int p)
{
	int i, j, l;
	gf_t c;
	int weight[n];
	int ww, m;

	for (i = 0; i < k; ++i) {
		c = v[i * n + p];

		if (c <= 1)
			continue;

		for (j = k; j < n; ++j)
			v[i * n + j] = gfdiv(v[i * n + j], c);
	}

	for (j = k; j < n; ++j) {
		int w_opt = k * GF_M * GF_M + 1;
		int c_opt = 0;

		for (c = 1; c < GF_Q; ++c) {
			int w = 0;

			for (i = 0; i < k; ++i)
				w += gf_weight[gfmul(v[i * n + j], c)];

			if (w < w_opt) {
				w_opt = w;
				c_opt = c;
			}
		}

		if (c_opt > 1) {
			for (i = 0; i < k; ++i)
				v[i * n + j] = gfmul(v[i * n + j], c_opt);
		}

		weight[j - k] = w_opt;
	}

	for (l = k; l < n - 1; ++l) {
		int w_opt = weight[l - k], j_opt = l;

		for (j = l + 1; j < n; ++j) {
			if (weight[j - k] < w_opt) {
				w_opt = weight[j - k];
				j_opt = j;
			}
		}

		if (j_opt == l)
			continue;

		for (i = 0; i < k; ++i) {
			c = v[i * n + l];
			v[i * n + l] = v[i * n + j_opt];
			v[i * n + j_opt] = c;
		}

		weight[j_opt - k] = weight[l - k];
		weight[l - k] = w_opt;
	}

	m = k < n - k ? k : n - k;
	ww = 0;

	for (j = 0; j < n - k; ++j)
		ww += weight[j];

	for (j = 0; j < m; ++j)
		ww += weight[j] * (m - j);

	for (i = 0; i < k; ++i) {
		weight[i] = 0;
		for (j = k; j < n; ++j)
			weight[i] += gf_weight[v[i * n + j]];
	}

	for (l = 0; l < k; ++l) {
		int w_opt = weight[l], i_opt = l;

		for (i = l + 1; i < k; ++i) {
			if (weight[i] < w_opt) {
				w_opt = weight[i];
				i_opt = i;
			}
		}

		if (i_opt == l)
			continue;

		for (j = k; j < n; ++j) {
			c = v[l * n + j];
			v[l * n + j] = v[i_opt * n + j];
			v[i_opt * n + j] = c;
		}

		weight[i_opt] = weight[l];
		weight[l] = w_opt;
	}

	return ww;
}

static int gf_minweight(gf_t *v, int n, int k)
{
	gf_t w[n * k];
	int p;
	int par_opt = k;
	int ww_opt;

	memcpy(w, v, n * k * sizeof(gf_t));

	ww_opt = gf_minweight_par(w, n, k, k);

	for (p = k + 1; p < n; ++p) {
		int ww;

		memcpy(w, v, n * k * sizeof(gf_t));

		ww = gf_minweight_par(w, n, k, p);

		if (ww < ww_opt) {
			ww_opt = ww;
			par_opt = p;
		}
	}

	return gf_minweight_par(v, n, k, par_opt);
}

static int gf_check_mds(gf_t *v, int n, int k)
{
	gf_t w[k * k];
	int i, j, l, m, s;
	int cnt = 0;

	for (m = (1 << k) - 1; m < (1 << n); m = next_choose(m), ++cnt) {
		s = m;

		for (l = 0; l < k; ++l) {
			j = __builtin_ctz(s);
			s ^= (1 << j);
			for (i = 0; i < k; ++i)
				w[i * k + l] = v[i * n + j];
		}

		BUG_ON(s != 0);

		if (gf_solve(w, k, k))
			return m;
	}

	return 0;
}

int N = 0, K = 0;

gf_t G[NMAX * NMAX];              // generator matrix
gf_t R[2 * RMAX * RMAX];          // repair matrix
int dx[RMAX], ex[RMAX];           // I/O mapping for repair matrix
block_t buf[NMAX];                // part buffer
unsigned rmask = 0;               // input mask for repair matrix


#define FOR for(i=0;i<SLEN;++i)

#define X1(v, a)          x[v][i] = y[a][i]
#define X2(v, a, b)       x[v][i] = y[a][i] ^ y[b][i]
#define X3(v, a, b, c)    x[v][i] = y[a][i] ^ y[b][i] ^ y[c][i]
#define X4(v, a, b, c, d) x[v][i] = y[a][i] ^ y[b][i] ^ y[c][i] ^ y[d][i]

static void mul_copy_block(block_t x, block_t y, gf_t z)
{        // X = Y*z
	int i;
	switch (z) {
		default:
		case  0: break;
		case  1: FOR { X1(0,0); X1(1,1); X1(2,2); X1(3,3); } break;
		case  2: FOR { X1(0,3); X2(1,0,3); X1(2,1); X1(3,2); } break;
		case  3: FOR { X2(0,0,3); X3(1,0,1,3); X2(2,1,2); X2(3,2,3); } break;
		case  4: FOR { X1(0,2); X2(1,2,3); X2(2,0,3); X1(3,1); } break;
		case  5: FOR { X2(0,0,2); X3(1,1,2,3); X3(2,0,2,3); X2(3,1,3); } break;
		case  6: FOR { X2(0,2,3); X2(1,0,2); X3(2,0,1,3); X2(3,1,2); } break;
		case  7: FOR { X3(0,0,2,3); X3(1,0,1,2); X4(2,0,1,2,3); X3(3,1,2,3); } break;
		case  8: FOR { X1(0,1); X2(1,1,2); X2(2,2,3); X2(3,0,3); } break;
		case  9: FOR { X2(0,0,1); X1(1,2); X1(2,3); X1(3,0); } break;
		case 10: FOR { X2(0,1,3); X4(1,0,1,2,3); X3(2,1,2,3); X3(3,0,2,3); } break;
		case 11: FOR { X3(0,0,1,3); X3(1,0,2,3); X2(2,1,3); X2(3,0,2); } break;
		case 12: FOR { X2(0,1,2); X2(1,1,3); X2(2,0,2); X3(3,0,1,3); } break;
		case 13: FOR { X3(0,0,1,2); X1(1,3); X1(2,0); X2(3,0,1); } break;
		case 14: FOR { X3(0,1,2,3); X2(1,0,1); X3(2,0,1,2); X4(3,0,1,2,3); } break;
		case 15: FOR { X4(0,0,1,2,3); X1(1,0); X2(2,0,1); X3(3,0,1,2); } break;
	}
}

#undef X1
#undef X2
#undef X3
#undef X4

#define X1(v, a)          x[v][i] ^= y[a][i]
#define X2(v, a, b)       x[v][i] ^= y[a][i] ^ y[b][i]
#define X3(v, a, b, c)    x[v][i] ^= y[a][i] ^ y[b][i] ^ y[c][i]
#define X4(v, a, b, c, d) x[v][i] ^= y[a][i] ^ y[b][i] ^ y[c][i] ^ y[d][i]

static void mul_xor_block(block_t x, block_t y, gf_t z)
{        // X ^= Y*z
	int i;
	switch (z) {
		default:
		case  0: break;
		case  1: FOR { X1(0,0); X1(1,1); X1(2,2); X1(3,3); } break;
		case  2: FOR { X1(0,3); X2(1,0,3); X1(2,1); X1(3,2); } break;
		case  3: FOR { X2(0,0,3); X3(1,0,1,3); X2(2,1,2); X2(3,2,3); } break;
		case  4: FOR { X1(0,2); X2(1,2,3); X2(2,0,3); X1(3,1); } break;
		case  5: FOR { X2(0,0,2); X3(1,1,2,3); X3(2,0,2,3); X2(3,1,3); } break;
		case  6: FOR { X2(0,2,3); X2(1,0,2); X3(2,0,1,3); X2(3,1,2); } break;
		case  7: FOR { X3(0,0,2,3); X3(1,0,1,2); X4(2,0,1,2,3); X3(3,1,2,3); } break;
		case  8: FOR { X1(0,1); X2(1,1,2); X2(2,2,3); X2(3,0,3); } break;
		case  9: FOR { X2(0,0,1); X1(1,2); X1(2,3); X1(3,0); } break;
		case 10: FOR { X2(0,1,3); X4(1,0,1,2,3); X3(2,1,2,3); X3(3,0,2,3); } break;
		case 11: FOR { X3(0,0,1,3); X3(1,0,2,3); X2(2,1,3); X2(3,0,2); } break;
		case 12: FOR { X2(0,1,2); X2(1,1,3); X2(2,0,2); X3(3,0,1,3); } break;
		case 13: FOR { X3(0,0,1,2); X1(1,3); X1(2,0); X2(3,0,1); } break;
		case 14: FOR { X3(0,1,2,3); X2(1,0,1); X3(2,0,1,2); X4(3,0,1,2,3); } break;
		case 15: FOR { X4(0,0,1,2,3); X1(1,0); X2(2,0,1); X3(3,0,1,2); } break;
	}
}

#undef X1
#undef X2
#undef X3
#undef X4

#undef FOR

void erasure_code_gf16_init(void)
{
	int m;

	BUG_ON(N < 1);
	BUG_ON(N > NMAX);
	BUG_ON(K < 1);
	BUG_ON(K > NMAX);
	BUG_ON(K > N);

	gf_init();
	gf_xvandermonde(G, N, K);
	gf_minweight(G, N, K);
	m = gf_check_mds(G, N, K);
	if (m)
		panic("generated erasure code is not MDS for input mask 0x%x.\n", m);
}

void erasure_code_gf16_encode(void)
{
	int i, j;

	/* Save user space vector registers */
	kernel_fpu_begin();

	for (j = K; j < N; ++j) {
		mul_copy_block(buf[j], buf[0], G[j]);

		for (i = 1; i < K; ++i)
			mul_xor_block(buf[j], buf[i], G[N * i + j]);
	}

	kernel_fpu_end();
}

void erasure_code_gf16_decode(int plast, unsigned rm)
{
	int i, j;

	if (plast >= K) {                        /* do reconstruction proper */
		int r = 0;

		/* Save user space vector registers */
		kernel_fpu_begin();

		if (rm == rmask) {                        /* can use old matrix */
			for (j = K; j <= plast; ++j) {
				if (!(rmask & (1 << j)))
					continue;

				++r;

				for (i = 0; i < K; ++i) {
					if (rmask & (1 << i))
						mul_xor_block(buf[j], buf[i], G[N * i + j]);
				}
			}
		} else {                        /* calculate repair matrix */
			int s = 0, rs = 0;
			rmask = rm;

			for (i = 0; i < K; ++i) {
				if (!(rmask & (1 << i)))
					dx[r++] = i;
			}

			for (j = K; j <= plast; ++j) {
				if (!(rmask & (1 << j)))
					continue;

				for (i = 0; i < K; ++i) {
					if (!(rmask & (1 << i)))
						R[rs++] = G[N * i + j];
					else
						mul_xor_block(buf[j], buf[i], G[N * i + j]);
				}

				for (i = 0; i < r; ++i)
					R[rs++] = (i == s);

				ex[s++] = j;
			}
			BUG_ON(r != s);
			BUG_ON(rs != 2 * r * s);

			if (gf_solve(R, 2 * r, r))
				panic("singular %dx%d submatrix. code is not MDS.", r, r);
		}

		for (j = 0; j < r; ++j) {
			mul_copy_block(buf[dx[j]], buf[ex[0]], R[(2 * j + 1) * r]);

			for (i = 1; i < r; ++i)
				mul_xor_block(buf[dx[j]], buf[ex[i]], R[(2 * j + 1) * r + i]);
		}

		kernel_fpu_end();
	}
}
