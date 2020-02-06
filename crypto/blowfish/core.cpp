#include "crypto/blowfish/core.hpp"

#define bf_F(R, S) ((((S[((R >> 24) & 0xff)] + S[0x0100 + ((R >> 16) & 0xff)]) ^ S[0x0200 + ((R >> 8) & 0xff)]) + S[0x0300+(R & 0xff)]) & 0xffffffffU)
#define bf_round_do(l, r, S, P, idx) ((l ^ P[idx]) ^ bf_F(r, S))

/*************************************************************************************************/
void WarGrey::DTPM::bf_encrypt(uint32 pL, uint32 pR, const uint32* P, const uint32* S, uint32* cL, uint32* cR) {
	uint32 l, r;

    r = pR;
    l = pL ^ P[0];
	r = bf_round_do(r, l, S, P, 1);
	l = bf_round_do(l, r, S, P, 2);
	r = bf_round_do(r, l, S, P, 3);
	l = bf_round_do(l, r, S, P, 4);
	r = bf_round_do(r, l, S, P, 5);
	l = bf_round_do(l, r, S, P, 6);
	r = bf_round_do(r, l, S, P, 7);
	l = bf_round_do(l, r, S, P, 8);
	r = bf_round_do(r, l, S, P, 9);
	l = bf_round_do(l, r, S, P, 10);
	r = bf_round_do(r, l, S, P, 11);
	l = bf_round_do(l, r, S, P, 12);
	r = bf_round_do(r, l, S, P, 13);
	l = bf_round_do(l, r, S, P, 14);
	r = bf_round_do(r, l, S, P, 15);
	l = bf_round_do(l, r, S, P, 16);
	r ^= P[17];

    (*cR) = l & 0xffffffffU;
    (*cL) = r & 0xffffffffU;
}

void WarGrey::DTPM::bf_decrypt(uint32 cL, uint32 cR, const uint32* P, const uint32* S, uint32* pL, uint32* pR) {
	uint32 l, r;
    
    r = cR;
    l = cL ^ P[17];
	r = bf_round_do(r, l, S, P, 16);
	l = bf_round_do(l, r, S, P, 15);
	r = bf_round_do(r, l, S, P, 14);
	l = bf_round_do(l, r, S, P, 13);
	r = bf_round_do(r, l, S, P, 12);
	l = bf_round_do(l, r, S, P, 11);
	r = bf_round_do(r, l, S, P, 10);
	l = bf_round_do(l, r, S, P, 9);
	r = bf_round_do(r, l, S, P, 8);
	l = bf_round_do(l, r, S, P, 7);
	r = bf_round_do(r, l, S, P, 6);
	l = bf_round_do(l, r, S, P, 5);
	r = bf_round_do(r, l, S, P, 4);
	l = bf_round_do(l, r, S, P, 3);
	r = bf_round_do(r, l, S, P, 2);
	l = bf_round_do(l, r, S, P, 1);
	r ^= P[0];

	(*pR) = l & 0xffffffffU;
	(*pL) = r & 0xffffffffU;
}
