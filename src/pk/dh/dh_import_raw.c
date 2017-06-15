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
  Import a DH key from a binary string
  @param in     The string to read
  @param inlen  The length of the input packet
  @param type   The type of key (PK_PRIVATE or PK_PUBLIC)
  @param base   The base (generator) in hex string
  @param prime  The prime in hex string
  @param key    [out] Where to import the key to
  @return CRYPT_OK if successful, on error all allocated memory is freed automatically
*/
int dh_import_raw(unsigned char *in, unsigned long inlen, int type,
                  const char *prime_hex, const char *base_hex, dh_key *key)
{
   int err;

   LTC_ARGCHK(in        != NULL);
   LTC_ARGCHK(base_hex  != NULL);
   LTC_ARGCHK(prime_hex != NULL);
   LTC_ARGCHK(key       != NULL);

   if ((err = mp_init_multi(&key->x, &key->y, &key->base, &key->prime, NULL)) != CRYPT_OK) {
      goto error;
   }
   if ((err = mp_read_radix(key->base, base_hex, 16)) != CRYPT_OK)                { goto error; }
   if ((err = mp_read_radix(key->prime, prime_hex, 16)) != CRYPT_OK)              { goto error; }

   if (type == PK_PRIVATE) {
      /* load the x value */
      if ((err = mp_read_unsigned_bin(key->x, in, inlen)) != CRYPT_OK)            { goto error; }
      /* compute y value */
      if ((err = mp_exptmod(key->base, key->x, key->prime, key->y)) != CRYPT_OK)  { goto error; }
      key->type = PK_PRIVATE;
   }
   else {
      /* load the y value */
      if ((err = mp_read_unsigned_bin(key->y, in, inlen)) != CRYPT_OK)            { goto error; }
      key->type = PK_PUBLIC;
      mp_clear(key->x);
      key->x = NULL;
   }

   /* check public key */
   if ((err = dh_check_pubkey(key)) != CRYPT_OK) {
      goto error;
   }

   return CRYPT_OK;

error:
   mp_clear_multi(key->prime, key->base, key->y, key->x, NULL);
   return err;
}

#endif /* LTC_MDH */
