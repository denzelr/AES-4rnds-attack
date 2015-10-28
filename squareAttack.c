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
		//printf("%d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d\n", key_poss[0][i0], key_poss[1][i1], key_poss[2][i2], key_poss[3][i3], key_poss[4][i4], key_poss[5][i5], key_poss[6][i6], key_poss[7][i7], key_poss[8][i8], key_poss[9][i9], key_poss[10][ia], key_poss[11][ib], key_poss[12][ic], key_poss[13][id], key_poss[14][ie], key_poss[15][iff]);
		rnd_keys[p][i0] = key_poss[0][i0];
		rnd_keys[p][i1] = key_poss[1][i1];
		rnd_keys[p][i2] = key_poss[2][i2];
		rnd_keys[p][i3] = key_poss[3][i3];
		rnd_keys[p][i4] = key_poss[4][i4];
		rnd_keys[p][i5] = key_poss[5][i5];
		rnd_keys[p][i6] = key_poss[6][i6];
		rnd_keys[p][i7] = key_poss[7][i7];
		rnd_keys[p][i8] = key_poss[8][i8];
		rnd_keys[p][i9] = key_poss[9][i9];
		rnd_keys[p][ia] = key_poss[10][ia];
		rnd_keys[p][ib] = key_poss[11][ib];
		rnd_keys[p][ic] = key_poss[12][ic];
		rnd_keys[p][id] = key_poss[13][id];
		rnd_keys[p][ie] = key_poss[14][ie];
		rnd_keys[p][iff] = key_poss[15][iff];
		p++;
		
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

void reverse_key_sched(u32 rk[/*4*(Nr + 1)*/], const u8 cipherKey[], int keyBits){
	/*
	int i = 0;
	u32 temp;

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
	u32 rk[16];
	for(int i = 0; rnd_keys[i] != 0; i++){
		unsigned char cipherkey[] = {key_poss[i][0], key_poss[i][1], key_poss[i][2], key_poss[i][3], key_poss[i][4], 
			key_poss[i][5], key_poss[i][6], key_poss[i][7], key_poss[i][8], key_poss[i][9], key_poss[i][10], 
			key_poss[i][11], key_poss[i][12], key_poss[i][13], key_poss[i][14], key_poss[i][15]};
			rijndaelKeySetupDec(rk, (unsigned char *)cipherkey, 128);
			//reverse_key_sched();
			print_hex_string(rk, 128);
	}

	
}

int main(int argc, char const *argv[])
{
	read_text();

	break_aes();
	combine_keys();
	
	
	

	return 0;
}