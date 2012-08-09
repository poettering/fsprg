#include <stdio.h>
#include <assert.h>
#include <gcrypt.h>

#include "fsprg.h"

static void printkey(void *key, size_t keylen)
{
  int i;
  for(i = 0; i < keylen; i++)
    printf("%02x ", ((unsigned char*)key)[i]);
  printf("\n");
}

#define SECPAR FSPRG_RECOMMENDED_SECPAR        // for normal use
//#define SECPAR 160                            // for debugging purposes
#define DELTA (uint64_t)1E3

int main(void)
{
  assert(gcry_check_version("1.4.5"));
  gcry_control(GCRYCTL_DISABLE_SECMEM, 0);
  gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);

  size_t msklen = FSPRG_mskinbytes(SECPAR);
  size_t mpklen = FSPRG_mpkinbytes(SECPAR);
  size_t seedlen = FSPRG_RECOMMENDED_SEEDLEN;   // arbitrary seed length
  size_t statelen = FSPRG_stateinbytes(SECPAR);
  size_t keylen = 10;                          // arbitrary output key length
  unsigned char msk[msklen];
  unsigned char mpk[mpklen];
  unsigned char seed[seedlen];
  unsigned char istate[statelen];
  unsigned char sstate[statelen];
  unsigned char key[keylen];
  int i;

  printf("Generating master keys (this may take some time)..."); fflush(stdout);
  FSPRG_GenMK(msk, mpk, NULL, 0, SECPAR);
  printf(" done!\n");

  gcry_randomize(seed, seedlen, GCRY_STRONG_RANDOM); /* optionally take seed from QR code */
  FSPRG_GenState0(istate, mpk, seed, seedlen);

  printf("key_{%8llu}:              ", (unsigned long long) FSPRG_GetEpoch(istate));
  FSPRG_GetKey(key, keylen, 0, istate);
  printkey(key, keylen);

  FSPRG_Seek(sstate, DELTA, msk, seed, seedlen);
  printf("key_{%8llu} (after seek): ", (unsigned long long) FSPRG_GetEpoch(sstate));
  FSPRG_GetKey(key, keylen, 0, sstate);
  printkey(key, keylen);

  for(i = 0; i < DELTA; i++)
    FSPRG_Evolve(istate);
  printf("key_{%8llu} (iterated):   ", (unsigned long long) FSPRG_GetEpoch(istate));
  FSPRG_GetKey(key, keylen, 0, istate);
  printkey(key, keylen);

  FSPRG_Seek(sstate, 2 * DELTA, msk, seed, seedlen);
  printf("key_{%8llu} (after seek): ", (unsigned long long) FSPRG_GetEpoch(sstate));
  FSPRG_GetKey(key, keylen, 0x1234, sstate);
  printkey(key, keylen);

  for(i = 0; i < DELTA; i++)
    FSPRG_Evolve(istate);
  printf("key_{%8llu} (iterated):   ", (unsigned long long) FSPRG_GetEpoch(istate));
  FSPRG_GetKey(key, keylen, 0x1234, istate);
  printkey(key, keylen);

  return 0;
}
