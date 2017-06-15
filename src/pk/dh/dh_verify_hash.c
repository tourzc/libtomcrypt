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
   Verify the signature given
   @param sig        The signature
   @param siglen     The length of the signature (octets)
   @param hash       The hash that was signed
   @param hashlen    The length of the hash (octets)
   @param stat       [out] Result of signature comparison, 1==valid, 0==invalid
   @param key        The public DH key that signed the hash
   @return CRYPT_OK if succsessful (even if signature is invalid)
*/
int dh_verify_hash(const unsigned char *sig, unsigned long siglen,
                   const unsigned char *hash, unsigned long hashlen,
                         int *stat, dh_key *key)
{
   void *a, *b, *m, *tmp;
   int err;

   LTC_ARGCHK(sig  != NULL);
   LTC_ARGCHK(hash != NULL);
   LTC_ARGCHK(stat != NULL);
   LTC_ARGCHK(key  != NULL);

   /* default to invalid */
   *stat = 0;

   /* init all bignums */
   if ((err = mp_init_multi(&a, &b, &m, &tmp, NULL)) != CRYPT_OK) {
      return err;
   }

   /* load a and b */
   if ((err = der_decode_sequence_multi(sig, siglen,
                                        LTC_ASN1_INTEGER, 1UL, a,
                                        LTC_ASN1_INTEGER, 1UL, b,
                                        LTC_ASN1_EOL,     0UL, NULL)) != CRYPT_OK) {
      goto error;
   }

   /* load m */
   if ((err = mp_read_unsigned_bin(m, (unsigned char *)hash, hashlen)) != CRYPT_OK) { goto error; }

   /* find g^m mod p */
   if ((err = mp_exptmod(key->base, m, key->prime, m)) != CRYPT_OK) { goto error; } /* m = g^m mod p */

   /* find y^a * a^b */
   if ((err = mp_exptmod(key->y, a, key->prime, tmp)) != CRYPT_OK)  { goto error; } /* tmp = y^a mod p */
   if ((err = mp_exptmod(a, b, key->prime, a)) != CRYPT_OK)         { goto error; } /* a = a^b mod p */
   if ((err = mp_mulmod(a, tmp, key->prime, a)) != CRYPT_OK)        { goto error; } /* a = y^a * a^b mod p */

   /* y^a * a^b == g^m ??? */
   if (mp_cmp(a, m) == 0) {
      *stat = 1;
   }

   /* clean up */
   err = CRYPT_OK;

error:
   mp_clear_multi(tmp, m, b, a, NULL);
   return err;
}

#endif /* LTC_MDH */
