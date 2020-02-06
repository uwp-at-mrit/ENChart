#include "crypto/blowfish/s_box.hpp"
#include "crypto/blowfish/core.hpp"

#include <cstring>

using namespace WarGrey::DTPM;

/**************************************************************************************************/
void WarGrey::DTPM::blowfish_initiate_boxes(const uint8* key, size_t size, BFBox *B) {
	const unsigned char *d, *end;
	const size_t roundp2 = sizeof(parray) / sizeof(uint32);
	uint32 ri;
	uint32 L = 0U;
	uint32 R = 0U;
	
    memcpy(B->parray, parray, sizeof(parray));
	memcpy(B->sbox, sbox, sizeof(sbox));
    
	if (size > roundp2 * 4) {
		size = roundp2 * 4;
	}

    d = key;
    end = &(key[size]);
    for (size_t i = 0; i < 18; i++) {
        ri = *(d++);
        if (d >= end) d = key;

        ri <<= 8;
        ri |= *(d++);
        if (d >= end) d = key;

        ri <<= 8;
        ri |= *(d++);
        if (d >= end) d = key;

        ri <<= 8;
        ri |= *(d++);
        if (d >= end) d = key;

        B->parray[i] ^= ri;
    }

    for (size_t i = 0; i < roundp2; i += 2) {
        bf_encrypt(L, R, B->parray, B->sbox, &L, &R);
        B->parray[i] = L;
        B->parray[i + 1] = R;
    }

    for (size_t i = 0; i < 4 * 256; i += 2) {
        bf_encrypt(L, R, B->parray, B->sbox, &L, &R);
        B->sbox[i] = L;
        B->sbox[i + 1] = R;
    }
}
