/*
 * mini-aes-main.c
 *
 *  Created on: Oct 9, 2012
 *      Author: mrz
 */

#include "common.h"
#include "mini-aes.h"

void check_for_same_key();

int main() {
	//u16 key[3] = { 0xC3F0, 0x30FF, 0x6696 };
	u16 key[16];
	u32 masterkey = 0x0000C3F0;
	s8 i;
	u8 Nr;
	u8 keylen;

	u64 masterkey64 = 0;
	u64 key64[12];

	// AES 64-bit Block

	/*
	 *
	//sbox4x4_8bit_Construct();
	pf("Test NibbleSub64 -> %016llX\n", NibbleSub64(0x0123456789ABCDEF));

	pf("Test NibbleSub64Inv -> %016llX\n", NibbleSub64Inv(NibbleSub64(0x0123456789ABCDEF)));

	pf("Test ShiftRow64    -> %016llX\n", ShiftRow64(0x0123456789ABCDEF));
	pf("Test ShiftRow64Inv -> %016llX\n", ShiftRow64Inv(ShiftRow64(0x0123456789ABCDEF)));

	pf("Nibble1 %X\n", MixColumn64_Nibble1(0x0123));
	pf("Nibble2 %X\n", MixColumn64_Nibble2(0x0123));
	pf("Nibble3 %X\n", MixColumn64_Nibble3(0x0123));
	pf("Nibble4 %X\n", MixColumn64_Nibble4(0x0123));
	u64 m64 = 0x0123456789ABCDEF;
	pf("Test MixColumn64    -> %016llX\n", MixColumn64(m64));
	pf("Test MixColumn64Inv -> %016llX\n", MixColumn64Inv(MixColumn64(m64)));
	//MixColumn64_Table_Construct();
	 *
	 */
	// key schedule
	/*
	keySchedule64(masterkey64, key64);

	pf("Number of rounds = %d\n", R);
	// encrypt
	u64 c64 = 0x9C63000011112222;
	pf("\nptext = %016llX\n", c64);
	pf("subkeys =\n"); for (i=0; i<(R+2); i++) pf("%016llX\n", key64[i]); pf("\n");

	c64 = encrypt64(c64, key64);
	pf("Encrypt -> %016llX\n\n", c64);

	pf("ctext = %016llX\n", c64);
	pf("subkeys =\n"); for (i=(R+1); i>=0; i--) pf("%016llX\n", key64[i]); pf("\n");
	c64 = decrypt64(c64, key64);
	pf("Decrypt -> %016llX\n", c64);

	u8 index = 3;
	u64 subkey = key64[index];
	pf("Test computing backwards %016llX : %016llX [%016llX]\n", subkey, subkeyComputeBackward(subkey, index), key64[index-1]);
	pf("Test computing forwards  %016llX : %016llX [%016llX]\n", subkey, subkeyComputeForward(subkey, index), key64[index+1]);
	*/
	// AES 64-bit Block

	//*
	pf("Testing je %x\n", NibbleSub(0x0123));
	pf("Test ShiftRow -> %04X\n", ShiftRow(0x4567));
	//MixColumn_Table_Construct();

	u16 c = 0x9C63; // the plaintext in Raphael's paper

	c = 0;
	masterkey = 0x0000C3F0;
	keylen = 8;

	// key schedule
	keySchedule(masterkey, key, keylen, &Nr);

	// encrypt
	pf("\nptext = %04X\n", c);
	pf("subkeys = "); for (i=0; i<(Nr+1); i++) pf("%04X ", key[i]); pf("\n");

	c = encrypt(c, key, Nr);
	pf("Encrypt -> %04X\n\n", c);

	pf("ctext = %04X\n", c);
	pf("subkeys = "); for (i=Nr; i>=0; i--) pf("%04X ", key[i]); pf("\n");
	c = decrypt(c, key, Nr);
	pf("Decrypt -> %04X\n", c);
	//*/

	check_for_same_key();
	return 0;
}

void check_for_same_key() {
	u16 key[16];
	u32 masterkey = 0x0000C3F0;
	u64 i;
	u8 Nr;
	u8 keylen;
	u16 c, x;
	u64 max, count=0;

	keylen = 8;

	max = (u64)pow(2, keylen*4);

	pf("max = %lu\n", max);

	c = 0;
	masterkey = 0;
	keySchedule(masterkey, key, keylen, &Nr);
	x = encrypt(c, key, Nr);

	for (i = 1; i < max; ++i) {
		masterkey = i;
		keySchedule(masterkey, key, keylen, &Nr);

		if (encrypt(c, key, Nr) == x) {
			pf("%x %x\n", c, i);
			count++;
		}
	}
	pf("Total: %d\n", count);

}

