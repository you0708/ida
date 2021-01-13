# FindCrypt
A Python implementation of IDA FindCrypt/FindCrypt2 plugin (see http://www.hexblog.com/?p=28).

## How to use
Execute findcrypt.py on your IDA. Tested on IDA 7.0+ for macOS.

## Supported constants
* aPLib: aPLib_magic
* xxHash32: xxHash32_PRIME32_[1-5]
* xxHash64: xxHash64_PRIME64_[1-5]
* zlib: zinflate_lengthStarts, zinflate_lengthExtraBits, zinflate_distanceStarts, zinflate_distanceExtraBits, zdeflate_lengthCodes
* Adler-32: Adler32_BASE
* Camellia: Camellia_sigma, Camellia_SBOX[1-4]
* DES: DES_ip, DES_fp, DES_ei, DES_sbox[1-8], DES_p32i, DES_pc[1-2]
* AES: Rijndael_sbox, Rijndael_inv_sbox, Rijndael_Te[0-4], Rijndael_Td[0-4]
* Blowfish: Blowfish_P_array, Blowfish_S_boxes
* CRC32: CRC32_m_tab_le, CRC32_m_tab_be
* CRC64: CRC64_ECMA
* FNV-1-32: FNV-1-32_prime, FNV-1-32_offset_basis
* FNV-1-64: FNV-1-64_prime, FNV-1-64_offset_basis
* MD5: MD5_T, MD5_initstate
* Salsa20_ChaCha: Salsa20_ChaCha_sigma, Salsa20_ChaCha_tau
* SHA1: SHA1_H
* SHA224: SHA224_H
* SHA256: SHA256_K, SHA256_H
* SHA512: SHA512_K
* RC5_RC6: RC5_RC6_PQ
* (XX)TEA: (XX)TEA_delta

## Todo
1. Add more constants - I always welcome your pull request :)
2. Performance improvement
