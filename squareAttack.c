//AES 4 rounds Square attack
//Ryan Denzel, Matt Binsfeld
//https://www.ime.usp.br/~rt/cranalysis/AESSimplified.pdf
//https://www.ime.usp.br/~rt/cranalysis/lucksRijndael.pdf

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

//0102030405060708090a0b0c0d0e0f00
//71fae486fafc990d4a44a21a7fac6b75
//For checking key possibilities
static unsigned char pt[16] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,0};
static unsigned char sln[16] = {0x71,0xfa,0xe4,0x86,0xfa,0xfc,0x99,0x0d,0x4a,0x44,0xa2,0x1a,0x7f,0xac,0x6b, 0x75};
unsigned char ct[16];
unsigned k[1024];
int p;


static const u32 rcon[] = {
	0x01000000, 0x02000000, 0x04000000, 0x08000000,
	0x10000000, 0x20000000, 0x40000000, 0x80000000,
	0x1B000000, 0x36000000,
};

const unsigned char SBOX[256] =   {
	0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
	0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
	0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
	0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
	0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
	0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
	0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
	0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
	0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
	0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
	0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
	0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
	0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
	0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
	0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
	0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 };

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
	int i0, i1, i2, i3, i4, i5, i6, i7, i8, i9, ia, ib, ic, id, ie, iff;
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

u32 SubWord(unsigned char *word){
	word[0] = SBOX[word[0]];
    word[1] = SBOX[word[1]];
    word[2] = SBOX[word[2]];
    word[3] = SBOX[word[3]];
    return *word;
}

unsigned char *RotWord(unsigned char *word){
	unsigned char *temp = &word[0];
    word[0] = word[1];
    word[1] = word[2];
    word[2] = word[3];
    word[3] = *temp;
    return word;
}

void reverse_schedule(unsigned char w[4*5]) {
    for(int i = 4*(5) - 1; i >= 4; i--)
        w[i-4] = w[i] ^ (i % 4 ? w[i-1] : SubWord(RotWord(&w[i-1])) ^ (rcon[i/4] << 24));
    for(int i = 0; i < 4; i++){
    	PUTU32(k + i*4, w[i]);
    }
}

void cycle_through_round_keys(){
	int i = 0;
	for(int i = 0; i < p; i++){
		unsigned char rk[16] = {rnd_keys[i][0], rnd_keys[i][1], rnd_keys[i][2], rnd_keys[i][3], rnd_keys[i][4], 
			rnd_keys[i][5], rnd_keys[i][6], rnd_keys[i][7], rnd_keys[i][8], rnd_keys[i][9], rnd_keys[i][10], 
			rnd_keys[i][11], rnd_keys[i][12], rnd_keys[i][13], rnd_keys[i][14], rnd_keys[i][15]};
			reverse_schedule(rk);
			rijndaelEncrypt(k, 4, pt, ct);
			print_hex_string((char *)ct, 16);
			printf("\n");
			if(!strcmp((char*)ct, (char*)sln)){
				printf("found key\n");
			}
	}

	
}

int main(int argc, char const *argv[])
{
	read_text();

	break_aes();
	combine_keys();
	cycle_through_round_keys();
	
	return 0;
}