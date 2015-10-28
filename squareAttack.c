//AES 4 rounds Square attack
//Ryan Denzel, Matt Binsfeld

#include "rijndael-alg-fst.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <assert.h>


#define SWAP(x) (_lrotl(x, 8) & 0x00ff00ff | _lrotr(x, 8) & 0xff00ff00)

#ifdef _MSC_VER
#define GETU32(p) SWAP(*((u32 *)(p)))
#define PUTU32(ct, st) { *((u32 *)(ct)) = SWAP((st)); }
#else
#define GETU32(pt) (((u32)(pt)[0] << 24) ^ ((u32)(pt)[1] << 16) ^ ((u32)(pt)[2] <<  8) ^ ((u32)(pt)[3]))
#define PUTU32(ct, st) { (ct)[0] = (u8)((st) >> 24); (ct)[1] = (u8)((st) >> 16); (ct)[2] = (u8)((st) >>  8); (ct)[3] = (u8)(st); }
#endif

static const u32 Te4[256] = {
    0x63636363U, 0x7c7c7c7cU, 0x77777777U, 0x7b7b7b7bU,
    0xf2f2f2f2U, 0x6b6b6b6bU, 0x6f6f6f6fU, 0xc5c5c5c5U,
    0x30303030U, 0x01010101U, 0x67676767U, 0x2b2b2b2bU,
    0xfefefefeU, 0xd7d7d7d7U, 0xababababU, 0x76767676U,
    0xcacacacaU, 0x82828282U, 0xc9c9c9c9U, 0x7d7d7d7dU,
    0xfafafafaU, 0x59595959U, 0x47474747U, 0xf0f0f0f0U,
    0xadadadadU, 0xd4d4d4d4U, 0xa2a2a2a2U, 0xafafafafU,
    0x9c9c9c9cU, 0xa4a4a4a4U, 0x72727272U, 0xc0c0c0c0U,
    0xb7b7b7b7U, 0xfdfdfdfdU, 0x93939393U, 0x26262626U,
    0x36363636U, 0x3f3f3f3fU, 0xf7f7f7f7U, 0xccccccccU,
    0x34343434U, 0xa5a5a5a5U, 0xe5e5e5e5U, 0xf1f1f1f1U,
    0x71717171U, 0xd8d8d8d8U, 0x31313131U, 0x15151515U,
    0x04040404U, 0xc7c7c7c7U, 0x23232323U, 0xc3c3c3c3U,
    0x18181818U, 0x96969696U, 0x05050505U, 0x9a9a9a9aU,
    0x07070707U, 0x12121212U, 0x80808080U, 0xe2e2e2e2U,
    0xebebebebU, 0x27272727U, 0xb2b2b2b2U, 0x75757575U,
    0x09090909U, 0x83838383U, 0x2c2c2c2cU, 0x1a1a1a1aU,
    0x1b1b1b1bU, 0x6e6e6e6eU, 0x5a5a5a5aU, 0xa0a0a0a0U,
    0x52525252U, 0x3b3b3b3bU, 0xd6d6d6d6U, 0xb3b3b3b3U,
    0x29292929U, 0xe3e3e3e3U, 0x2f2f2f2fU, 0x84848484U,
    0x53535353U, 0xd1d1d1d1U, 0x00000000U, 0xededededU,
    0x20202020U, 0xfcfcfcfcU, 0xb1b1b1b1U, 0x5b5b5b5bU,
    0x6a6a6a6aU, 0xcbcbcbcbU, 0xbebebebeU, 0x39393939U,
    0x4a4a4a4aU, 0x4c4c4c4cU, 0x58585858U, 0xcfcfcfcfU,
    0xd0d0d0d0U, 0xefefefefU, 0xaaaaaaaaU, 0xfbfbfbfbU,
    0x43434343U, 0x4d4d4d4dU, 0x33333333U, 0x85858585U,
    0x45454545U, 0xf9f9f9f9U, 0x02020202U, 0x7f7f7f7fU,
    0x50505050U, 0x3c3c3c3cU, 0x9f9f9f9fU, 0xa8a8a8a8U,
    0x51515151U, 0xa3a3a3a3U, 0x40404040U, 0x8f8f8f8fU,
    0x92929292U, 0x9d9d9d9dU, 0x38383838U, 0xf5f5f5f5U,
    0xbcbcbcbcU, 0xb6b6b6b6U, 0xdadadadaU, 0x21212121U,
    0x10101010U, 0xffffffffU, 0xf3f3f3f3U, 0xd2d2d2d2U,
    0xcdcdcdcdU, 0x0c0c0c0cU, 0x13131313U, 0xececececU,
    0x5f5f5f5fU, 0x97979797U, 0x44444444U, 0x17171717U,
    0xc4c4c4c4U, 0xa7a7a7a7U, 0x7e7e7e7eU, 0x3d3d3d3dU,
    0x64646464U, 0x5d5d5d5dU, 0x19191919U, 0x73737373U,
    0x60606060U, 0x81818181U, 0x4f4f4f4fU, 0xdcdcdcdcU,
    0x22222222U, 0x2a2a2a2aU, 0x90909090U, 0x88888888U,
    0x46464646U, 0xeeeeeeeeU, 0xb8b8b8b8U, 0x14141414U,
    0xdedededeU, 0x5e5e5e5eU, 0x0b0b0b0bU, 0xdbdbdbdbU,
    0xe0e0e0e0U, 0x32323232U, 0x3a3a3a3aU, 0x0a0a0a0aU,
    0x49494949U, 0x06060606U, 0x24242424U, 0x5c5c5c5cU,
    0xc2c2c2c2U, 0xd3d3d3d3U, 0xacacacacU, 0x62626262U,
    0x91919191U, 0x95959595U, 0xe4e4e4e4U, 0x79797979U,
    0xe7e7e7e7U, 0xc8c8c8c8U, 0x37373737U, 0x6d6d6d6dU,
    0x8d8d8d8dU, 0xd5d5d5d5U, 0x4e4e4e4eU, 0xa9a9a9a9U,
    0x6c6c6c6cU, 0x56565656U, 0xf4f4f4f4U, 0xeaeaeaeaU,
    0x65656565U, 0x7a7a7a7aU, 0xaeaeaeaeU, 0x08080808U,
    0xbabababaU, 0x78787878U, 0x25252525U, 0x2e2e2e2eU,
    0x1c1c1c1cU, 0xa6a6a6a6U, 0xb4b4b4b4U, 0xc6c6c6c6U,
    0xe8e8e8e8U, 0xddddddddU, 0x74747474U, 0x1f1f1f1fU,
    0x4b4b4b4bU, 0xbdbdbdbdU, 0x8b8b8b8bU, 0x8a8a8a8aU,
    0x70707070U, 0x3e3e3e3eU, 0xb5b5b5b5U, 0x66666666U,
    0x48484848U, 0x03030303U, 0xf6f6f6f6U, 0x0e0e0e0eU,
    0x61616161U, 0x35353535U, 0x57575757U, 0xb9b9b9b9U,
    0x86868686U, 0xc1c1c1c1U, 0x1d1d1d1dU, 0x9e9e9e9eU,
    0xe1e1e1e1U, 0xf8f8f8f8U, 0x98989898U, 0x11111111U,
    0x69696969U, 0xd9d9d9d9U, 0x8e8e8e8eU, 0x94949494U,
    0x9b9b9b9bU, 0x1e1e1e1eU, 0x87878787U, 0xe9e9e9e9U,
    0xcecececeU, 0x55555555U, 0x28282828U, 0xdfdfdfdfU,
    0x8c8c8c8cU, 0xa1a1a1a1U, 0x89898989U, 0x0d0d0d0dU,
    0xbfbfbfbfU, 0xe6e6e6e6U, 0x42424242U, 0x68686868U,
    0x41414141U, 0x99999999U, 0x2d2d2d2dU, 0x0f0f0f0fU,
    0xb0b0b0b0U, 0x54545454U, 0xbbbbbbbbU, 0x16161616U,
};

static const u32 rcon[] = {
	0x01000000, 0x02000000, 0x04000000, 0x08000000,
	0x10000000, 0x20000000, 0x40000000, 0x80000000,
	0x1B000000, 0x36000000, /* for 128-bit blocks, Rijndael never uses more than 10 rcon values */
};

const unsigned char SBOX_i[] = {	
					0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
					0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
					0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
					0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
					0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
					0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
					0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
					0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
					0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
					0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
					0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
					0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
					0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
					0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
					0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
					0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D };

unsigned char state[257][17];
unsigned char key_poss[16][16] = {0};
unsigned char rnd_keys[4096][16] = {0};

void read_text(){
	   FILE *fp;
	   char *line = NULL;
	   size_t len = 0;
	   ssize_t read;
	   size_t count = 0;
	   int check;

	   fp = fopen("ciphertext.txt", "r");
	   if (fp == NULL)
	       printf("File not found\n");

	   while ((read = getline(&line, &len, fp)) != -1) {
    		
	    	for(int i = 0; i < 16; i++){
	        	sscanf(line, "%2hhx", &state[count][i]);
	        	line += 2;
	    	}
	    	count++;
		}

	   fclose(fp);

}

void break_aes(){

	int i, j, k;
	unsigned int temp1, temp2;
	char store[256] = {0};

	//All i, j, values
	for(i = 0; i < 16; i++){
		int p = 0;
		//Exhaust keys
		for(j = 0; j < 256; j++){
			temp2 = 0;
			//For all ciphertexts
			for(k = 0; k < 256; k++){
				temp1 = state[k][i] ^ j;
				temp2 ^= SBOX_i[temp1];
			}
			if(temp2 == 0){
				//printf("Key found for cell %d: %d\n", i, j);
				key_poss[i][p] = j;
				p++;
			}
		}
	}

}

void combine_keys(){
	int i0, i1, i2, i3, i4, i5, i6, i7, i8, i9, ia, ib, ic, id, ie, iff, p;
	for(i0 = 0; key_poss[0][i0] != 0; i0++){
	for(i1 = 0; key_poss[1][i1] != 0; i1++){
	for(i2 = 0; key_poss[2][i2] != 0; i2++){
	for(i3 = 0; key_poss[3][i3] != 0; i3++){
	for(i4 = 0; key_poss[4][i4] != 0; i4++){
	for(i5 = 0; key_poss[5][i5] != 0; i5++){
	for(i6 = 0; key_poss[6][i6] != 0; i6++){
	for(i7 = 0; key_poss[7][i7] != 0; i7++){
	for(i8 = 0; key_poss[8][i8] != 0; i8++){
	for(i9 = 0; key_poss[9][i9] != 0; i9++){
	for(ia = 0; key_poss[10][ia] != 0; ia++){
	for(ib = 0; key_poss[11][ib] != 0; ib++){
	for(ic = 0; key_poss[12][ic] != 0; ic++){
	for(id = 0; key_poss[13][id] != 0; id++){
	for(ie = 0; key_poss[14][ie] != 0; ie++){
	for(iff = 0; key_poss[15][iff] != 0; iff++){
		//printf("keyposs = %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d\n", key_poss[0][i0], key_poss[1][i1], key_poss[2][i2], key_poss[3][i3], key_poss[4][i4], key_poss[5][i5], key_poss[6][i6], key_poss[7][i7], key_poss[8][i8], key_poss[9][i9], key_poss[10][ia], key_poss[11][ib], key_poss[12][ic], key_poss[13][id], key_poss[14][ie], key_poss[15][iff]);
		rnd_keys[p][0] = key_poss[0][i0];
		rnd_keys[p][1] = key_poss[1][i1];
		rnd_keys[p][2] = key_poss[2][i2];
		rnd_keys[p][3] = key_poss[3][i3];
		rnd_keys[p][4] = key_poss[4][i4];
		rnd_keys[p][5] = key_poss[5][i5];
		rnd_keys[p][6] = key_poss[6][i6];
		rnd_keys[p][7] = key_poss[7][i7];
		rnd_keys[p][8] = key_poss[8][i8];
		rnd_keys[p][9] = key_poss[9][i9];
		rnd_keys[p][10] = key_poss[10][ia];
		rnd_keys[p][11] = key_poss[11][ib];
		rnd_keys[p][12] = key_poss[12][ic];
		rnd_keys[p][13] = key_poss[13][id];
		rnd_keys[p][14] = key_poss[14][ie];
		rnd_keys[p][15] = key_poss[15][iff];
		p++;
		//printf("rnd_keys: %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d\n", rnd_keys[0][i0], rnd_keys[1][i1], rnd_keys[2][i2], rnd_keys[3][i3], rnd_keys[4][i4], rnd_keys[5][i5], rnd_keys[6][i6], rnd_keys[7][i7], rnd_keys[8][i8], rnd_keys[9][i9], rnd_keys[10][ia], rnd_keys[11][ib], rnd_keys[12][ic], rnd_keys[13][id], rnd_keys[14][ie], rnd_keys[15][iff]);
	}}}}}}}}}}}}}}}}
}

void print_hex_string(char* buf, int len)
{
    int i;

    if (len==0) { printf("<empty string>"); return; }
    if (len>=40) {
        for (i = 0; i < 10; i++)
             printf("%02x", *((unsigned char *)buf + i));
        printf(" ... ");
        for (i = len-10; i < len; i++)
             printf("%02x", *((unsigned char *)buf + i));
        printf(" [%d bytes]", len);
        return;
    }
    for (i = 0; i < len; i++)
        printf("%02x", *((unsigned char *)buf + i));
}

void reverse_key_sched(){
	
	int i = 0;
	u32 temp;
	/*
	rk[0] = GETU32(cipherKey     );
	rk[1] = GETU32(cipherKey +  4);
	rk[2] = GETU32(cipherKey +  8);
	rk[3] = GETU32(cipherKey + 12);
	if (keyBits == 128) {
		for (;;) {
			temp  = rk[3];
			rk[4] = rk[0] ^
				(Te4[(temp >> 16) & 0xff] & 0xff000000) ^
				(Te4[(temp >>  8) & 0xff] & 0x00ff0000) ^
				(Te4[(temp      ) & 0xff] & 0x0000ff00) ^
				(Te4[(temp >> 24)       ] & 0x000000ff) ^
				rcon[i];
			rk[5] = rk[1] ^ rk[4];
			rk[6] = rk[2] ^ rk[5];
			rk[7] = rk[3] ^ rk[6];
			if (++i == 10) {
				return 10;
			}
			rk += 4;
		}
	}*/
	unsigned char ciphertexts[16];
	//hard coded rnd_keys length for this attack at 1536
	for(int i = 0; i < 1536; i++){
		unsigned char rk[] = {rnd_keys[i][0], rnd_keys[i][1], rnd_keys[i][2], rnd_keys[i][3], rnd_keys[i][4], 
			rnd_keys[i][5], rnd_keys[i][6], rnd_keys[i][7], rnd_keys[i][8], rnd_keys[i][9], rnd_keys[i][10], 
			rnd_keys[i][11], rnd_keys[i][12], rnd_keys[i][13], rnd_keys[i][14], rnd_keys[i][15]};
			for(int j = 0; j < 16; j++){
				printf("%d ", rk[j]);
			}
			printf("\n");
	}

	
}

int main(int argc, char const *argv[])
{
	read_text();

	break_aes();
	combine_keys();
	reverse_key_sched();
	
	return 0;
}