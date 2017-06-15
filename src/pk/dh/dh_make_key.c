/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 */

#include "tomcrypt.h"

#ifdef LTC_MDH

/**
  Make a DH key (custom DH group) [private key pair]
  @param prng       An active PRNG state
  @param wprng      The index for the PRNG you desire to use
  @param prime_hex  The prime p (hexadecimal string)
  @param base_hex   The base g (hexadecimal string)
  @param key        [out] Where the newly created DH key will be stored
  @return CRYPT_OK if successful, note: on error all allocated memory will be freed automatically.
*/
int dh_make_key_ex(prng_state *prng, int wprng, char *prime_hex, char *base_hex, dh_key *key)
{
   unsigned char *buf;
   unsigned long keysize;
   int err;

   LTC_ARGCHK(key  != NULL);
   LTC_ARGCHK(prng != NULL);
   LTC_ARGCHK(prime_hex != NULL);
   LTC_ARGCHK(base_hex  != NULL);

   /* good prng? */
   if ((err = prng_is_valid(wprng)) != CRYPT_OK) {
      return err;
   }

   /* init big numbers */
   if ((err = mp_init_multi(&key->x, &key->y, &key->base, &key->prime, NULL)) != CRYPT_OK) {
      return err;
   }

   /* load the prime and the base */
   if ((err = mp_read_radix(key->base, base_hex, 16)) != CRYPT_OK)   { goto freemp; }
   if ((err = mp_read_radix(key->prime, prime_hex, 16)) != CRYPT_OK) { goto freemp; }

   keysize = dh_groupsize_to_keysize(mp_unsigned_bin_size(key->prime));
   if (keysize == 0) {
      err = CRYPT_INVALID_KEYSIZE;
      goto freemp;
   }

   /* allocate buffer */
   buf = XMALLOC(keysize);
   if (buf == NULL) {
      err = CRYPT_MEM;
      goto freemp;
   }

   key->type = PK_PRIVATE;
   do {
      /* make up random buf */
      if (prng_descriptor[wprng].read(buf, keysize, prng) != keysize) {
         err = CRYPT_ERROR_READPRNG;
         goto freebuf;
      }
      /* load the x value - private key */
      if ((err = mp_read_unsigned_bin(key->x, buf, keysize)) != CRYPT_OK) {
         goto freebuf;
      }
      /* compute the y value - public key */
      if ((err = mp_exptmod(key->base, key->x, key->prime, key->y)) != CRYPT_OK) {
         goto freebuf;
      }
   } while (dh_check_pubkey(key) != CRYPT_OK);

   /* success */
   return CRYPT_OK;

freebuf:
   zeromem(buf, keysize);
   XFREE(buf);
freemp:
   mp_clear_multi(key->x, key->y, key->base, key->prime, NULL);
   return err;
}

/**
  Make a DH key (use built-in DH groups) [private key pair]
  @param prng       An active PRNG state
  @param wprng      The index for the PRNG you desire to use
  @param groupsize  The size (octets) of used DH group
  @param key        [out] Where the newly created DH key will be stored
  @return CRYPT_OK if successful, note: on error all allocated memory will be freed automatically.
*/
int dh_make_key(prng_state *prng, int wprng, int groupsize, dh_key *key)
{
   int i;

   for (i = 0; (groupsize > ltc_dh_sets[i].size) && (ltc_dh_sets[i].size != 0); i++);
   if (ltc_dh_sets[i].size == 0) return CRYPT_INVALID_KEYSIZE;

   return dh_make_key_ex(prng, wprng, ltc_dh_sets[i].prime, ltc_dh_sets[i].base, key);
}

#endif /* LTC_MDH */
