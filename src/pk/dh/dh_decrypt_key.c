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
   Decrypt a DH encrypted symmetric key
   @param in       The DH encrypted packet
   @param inlen    The length of the DH encrypted packet
   @param out      The plaintext
   @param outlen   [in/out]  The max size and resulting size of the plaintext
   @param key      The private DH key corresponding to the public key that encrypted the plaintext
   @return CRYPT_OK if successful
*/
int dh_decrypt_key(const unsigned char *in, unsigned long inlen,
                         unsigned char *out, unsigned long *outlen,
                         dh_key *key)
{
   unsigned char *shared_secret, *skey, *pub_expt;
   char *prime_hex, *base_hex;
   unsigned long  x, z, hashOID[32];
   int            hash, err;
   ltc_asn1_list  decode[3];
   dh_key         pubkey;

   LTC_ARGCHK(in     != NULL);
   LTC_ARGCHK(out    != NULL);
   LTC_ARGCHK(outlen != NULL);
   LTC_ARGCHK(key    != NULL);

   /* right key type? */
   if (key->type != PK_PRIVATE) {
      return CRYPT_PK_NOT_PRIVATE;
   }

   /* decode to find out hash */
   LTC_SET_ASN1(decode, 0, LTC_ASN1_OBJECT_IDENTIFIER, hashOID, sizeof(hashOID)/sizeof(hashOID[0]));
   if ((err = der_decode_sequence(in, inlen, decode, 1)) != CRYPT_OK) {
      return err;
   }
   hash = find_hash_oid(hashOID, decode[0].size);
   if (hash_is_valid(hash) != CRYPT_OK) {
      return CRYPT_INVALID_PACKET;
   }

   /* allocate ram */
   prime_hex = XMALLOC(mp_unsigned_bin_size(key->prime) * 2 + 1);
   base_hex  = XMALLOC(mp_unsigned_bin_size(key->base) * 2 + 1);
   pub_expt      = XMALLOC(DH_BUF_SIZE);
   shared_secret = XMALLOC(DH_BUF_SIZE);
   skey          = XMALLOC(MAXBLOCKSIZE);
   if (shared_secret == NULL || skey == NULL) {
      if (shared_secret != NULL) {
         XFREE(shared_secret);
      }
      if (pub_expt != NULL) {
         XFREE(pub_expt);
      }
      if (skey != NULL) {
         XFREE(skey);
      }
      if (prime_hex != NULL) {
         XFREE(skey);
      }
      if (base_hex != NULL) {
         XFREE(skey);
      }
      return CRYPT_MEM;
   }

   /* decode "public key" + "encrypted data" */
   LTC_SET_ASN1(decode, 1, LTC_ASN1_OCTET_STRING, pub_expt, DH_BUF_SIZE);
   LTC_SET_ASN1(decode, 2, LTC_ASN1_OCTET_STRING, skey, MAXBLOCKSIZE);
   if ((err = der_decode_sequence(in, inlen, decode, 3)) != CRYPT_OK) {
      goto LBL_ERR;
   }

   /* import DH key (public) */
   mp_tohex(key->prime, prime_hex);
   mp_tohex(key->base, base_hex);
   if ((err = dh_import_raw(decode[1].data, decode[1].size, PK_PUBLIC, prime_hex, base_hex, &pubkey)) != CRYPT_OK) {
      goto LBL_ERR;
   }

   /* make "shared key" */
   x = DH_BUF_SIZE;
   if ((err = dh_shared_secret(key, &pubkey, shared_secret, &x)) != CRYPT_OK) {
      dh_free(&pubkey);
      goto LBL_ERR;
   }
   dh_free(&pubkey);

   /* compute "decryption key" = hash("shared key") - it's stored back in shared_secret  */
   z = MIN(DH_BUF_SIZE, MAXBLOCKSIZE);
   if ((err = hash_memory(hash, shared_secret, x, shared_secret, &z)) != CRYPT_OK) {
      goto LBL_ERR;
   }

   /* ensure that "decryption key" is at least as big as the "encrypted data" */
   if (decode[2].size > z) {
      err = CRYPT_INVALID_PACKET;
      goto LBL_ERR;
   }

   /* Avoid buffer overflow */
   if (*outlen < decode[2].size) {
      *outlen = decode[2].size;
      err = CRYPT_BUFFER_OVERFLOW;
      goto LBL_ERR;
   }

   /* Decrypt "encrypted data" */
   for (x = 0; x < decode[2].size; x++) {
     out[x] = skey[x] ^ shared_secret[x];
   }
   *outlen = x;

   /* Success */
   err = CRYPT_OK;

LBL_ERR:
#ifdef LTC_CLEAN_STACK
   zeromem(pub_expt,      DH_BUF_SIZE);
   zeromem(shared_secret, DH_BUF_SIZE);
   zeromem(skey,          MAXBLOCKSIZE);
#endif
   XFREE(pub_expt);
   XFREE(shared_secret);
   XFREE(skey);
   XFREE(prime_hex);
   XFREE(base_hex);
   return err;
}

#endif /* LTC_MDH */
