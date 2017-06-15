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

/* perform an ElGamal Signature of a hash
 *
 * The math works as follows.  x is the private key, M is the message to sign

 1.  pick a random k
 2.  compute a = g^k mod p
 3.  compute b = (M - xa)/k mod p
 4.  Send (a,b)

 Now to verify with y=g^x mod p, a and b

 1.  compute y^a * a^b = g^(xa) * g^(k*(M-xa)/k)
                       = g^(xa + (M - xa))
                       = g^M [all mod p]

 2.  Compare against g^M mod p [based on input hash].
 3.  If result of #2 == result of #1 then signature valid
*/

/**
  Sign a message digest using a DH private key
  @param in      The data to sign
  @param inlen   The length of the input (octets)
  @param out     [out] The destination of the signature
  @param outlen  [in/out] The max size and resulting size of the output
  @param prng    An active PRNG state
  @param wprng   The index of the PRNG desired
  @param key     A private DH key
  @return CRYPT_OK if successful
*/
int dh_sign_hash(const unsigned char *in,  unsigned long inlen,
                       unsigned char *out, unsigned long *outlen,
                       prng_state *prng, int wprng, dh_key *key)
{
   void          *a, *b, *k, *m, *p1, *tmp;
   unsigned char *buf;
   unsigned long  keysize;
   int            err;

   LTC_ARGCHK(in     != NULL);
   LTC_ARGCHK(out    != NULL);
   LTC_ARGCHK(outlen != NULL);
   LTC_ARGCHK(key    != NULL);

   /* check parameters */
   if (key->type != PK_PRIVATE) {
      return CRYPT_PK_NOT_PRIVATE;
   }

   if ((err = prng_is_valid(wprng)) != CRYPT_OK) {
      return err;
   }

   keysize = dh_groupsize_to_keysize(mp_unsigned_bin_size(key->prime));
   if (keysize <= 0) {
      return CRYPT_PK_INVALID_TYPE;
   }

   /* allocate ram for buf */
   buf = XMALLOC(keysize);

   /* make up a random value k,
    * since the order of the group is prime
    * we need not check if gcd(k, r) is 1
    */
   if (prng_descriptor[wprng].read(buf, keysize, prng) != keysize) {
      err = CRYPT_ERROR_READPRNG;
      goto LBL_ERR_1;
   }

   /* init bignums */
   if ((err = mp_init_multi(&a, &b, &k, &m, &p1, &tmp, NULL)) != CRYPT_OK) {
      goto LBL_ERR;
   }

   /* load k and m */
   if ((err = mp_read_unsigned_bin(m, (unsigned char *)in, inlen)) != CRYPT_OK) { goto LBL_ERR; }
   if ((err = mp_read_unsigned_bin(k, buf, keysize)) != CRYPT_OK)               { goto LBL_ERR; }

   /* compute p1 */
   if ((err = mp_sub_d(key->prime, 1, p1)) != CRYPT_OK)                         { goto LBL_ERR; }
   if ((err = mp_div_2(p1, p1)) != CRYPT_OK)                                    { goto LBL_ERR; } /* p1 = (p-1)/2 */

   /* now get a = g^k mod p */
   if ((err = mp_exptmod(key->base, k, key->prime, a)) != CRYPT_OK)             { goto LBL_ERR; }

   /* now find M = xa + kb mod p1 or just b = (M - xa)/k mod p1 */
   if ((err = mp_invmod(k, p1, k)) != CRYPT_OK)                                 { goto LBL_ERR; } /* k = 1/k mod p1 */
   if ((err = mp_mulmod(a, key->x, p1, tmp)) != CRYPT_OK)                       { goto LBL_ERR; } /* tmp = xa */
   if ((err = mp_submod(m, tmp, p1, tmp)) != CRYPT_OK)                          { goto LBL_ERR; } /* tmp = M - xa */
   if ((err = mp_mulmod(k, tmp, p1, b)) != CRYPT_OK)                            { goto LBL_ERR; } /* b = (M - xa)/k */

   err = der_encode_sequence_multi(out, outlen,
                                   LTC_ASN1_INTEGER, 1UL, a,
                                   LTC_ASN1_INTEGER, 1UL, b,
                                   LTC_ASN1_EOL,     0UL, NULL);

LBL_ERR:
   mp_clear_multi(tmp, p1, m, k, b, a, NULL);
LBL_ERR_1:
   XFREE(buf);
   return err;
}

#endif /* LTC_MDH */
