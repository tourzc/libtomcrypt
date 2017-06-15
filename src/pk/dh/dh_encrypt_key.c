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
  Encrypt a short symmetric key with a public DH key
  @param in        The symmetric key to encrypt
  @param inlen     The length of the key (octets)
  @param out       [out] The ciphertext
  @param outlen    [in/out]  The max size and resulting size of the ciphertext
  @param prng      An active PRNG state
  @param wprng     The index of the PRNG desired
  @param hash      The index of the hash desired (must produce a digest of size >= the size of the plaintext)
  @param key       The public key you wish to encrypt with.
  @return CRYPT_OK if successful
*/
int dh_encrypt_key(const unsigned char *in,   unsigned long inlen,
                         unsigned char *out,  unsigned long *outlen,
                         prng_state *prng, int wprng, int hash,
                         dh_key *key)
{
    unsigned char *pub_expt, *dh_shared, *skey;
    dh_key        pubkey;
    unsigned long x, z, pubkeysize;
    int           err;
    char          *prime_hex, *base_hex;

    LTC_ARGCHK(in     != NULL);
    LTC_ARGCHK(out    != NULL);
    LTC_ARGCHK(outlen != NULL);
    LTC_ARGCHK(key    != NULL);

    /* check that wprng/hash are not invalid */
    if ((err = prng_is_valid(wprng)) != CRYPT_OK) {
       return err;
    }

    if ((err = hash_is_valid(hash)) != CRYPT_OK) {
       return err;
    }

    if (inlen > hash_descriptor[hash].hashsize)  {
        return CRYPT_INVALID_HASH;
    }

    /* allocate memory */
    pub_expt  = XMALLOC(DH_BUF_SIZE);
    dh_shared = XMALLOC(DH_BUF_SIZE);
    skey      = XMALLOC(MAXBLOCKSIZE);
    if (pub_expt == NULL || dh_shared == NULL || skey == NULL) {
       if (pub_expt != NULL) {
          XFREE(pub_expt);
       }
       if (dh_shared != NULL) {
          XFREE(dh_shared);
       }
       if (skey != NULL) {
          XFREE(skey);
       }
       return CRYPT_MEM;
    }

    /* temporarily abuse pub_expt + dh_shared buffers for prime_hex + base_hex */
    if ((mp_unsigned_bin_size(key->prime) * 2 + 1 > DH_BUF_SIZE) ||
        (mp_unsigned_bin_size(key->base) * 2 + 1 > DH_BUF_SIZE)) {
       err = CRYPT_MEM;
       goto LBL_ERR;
    }
    prime_hex = (char*)pub_expt;
    base_hex  = (char*)dh_shared;
    mp_tohex(key->prime, prime_hex);
    mp_tohex(key->base, base_hex);

    /* make a random key and export the public part */
    if ((err = dh_make_key_ex(prng, wprng, prime_hex, base_hex, &pubkey)) != CRYPT_OK) {
       goto LBL_ERR;
    }
    pubkeysize = DH_BUF_SIZE;
    if ((err = dh_export_raw(pub_expt, &pubkeysize, PK_PUBLIC, &pubkey)) != CRYPT_OK) {
       dh_free(&pubkey);
       goto LBL_ERR;
    }

    /* make shared key */
    x = DH_BUF_SIZE;
    if ((err = dh_shared_secret(&pubkey, key, dh_shared, &x)) != CRYPT_OK) {
       dh_free(&pubkey);
       goto LBL_ERR;
    }
    dh_free(&pubkey);

    z = MAXBLOCKSIZE;
    if ((err = hash_memory(hash, dh_shared, x, skey, &z)) != CRYPT_OK) {
       goto LBL_ERR;
    }

    /* Encrypt key */
    for (x = 0; x < inlen; x++) {
      skey[x] ^= in[x];
    }

    err = der_encode_sequence_multi(out, outlen,
                                    LTC_ASN1_OBJECT_IDENTIFIER, hash_descriptor[hash].OIDlen, hash_descriptor[hash].OID,
                                    LTC_ASN1_OCTET_STRING,      pubkeysize,                   pub_expt,
                                    LTC_ASN1_OCTET_STRING,      inlen,                        skey,
                                    LTC_ASN1_EOL,               0UL,                          NULL);

LBL_ERR:
#ifdef LTC_CLEAN_STACK
    zeromem(pub_expt,  DH_BUF_SIZE);
    zeromem(dh_shared, DH_BUF_SIZE);
    zeromem(skey,      MAXBLOCKSIZE);
#endif
    XFREE(skey);
    XFREE(dh_shared);
    XFREE(pub_expt);
    return err;
}

#endif /* LTC_MDH */
