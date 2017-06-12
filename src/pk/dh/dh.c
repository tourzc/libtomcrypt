/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 *
 * Tom St Denis, tomstdenis@gmail.com, http://libtomcrypt.org
 */
#include "tomcrypt.h"

/**
  @file dh.c
  DH crypto, Tom St Denis
*/

#ifdef LTC_MDH

#include "dh_static.h"

/**
   Get the min and max DH group sizes (octets)
   @param low    [out] The smallest group size supported
   @param high   [out] The largest group size supported
*/
void dh_groupsizes(int *low, int *high)
{
   int x;
   LTC_ARGCHKVD(low != NULL);
   LTC_ARGCHKVD(high != NULL);
   *low  = INT_MAX;
   *high = 0;
   for (x = 0; ltc_dh_sets[x].size != 0; x++) {
       if (*low > ltc_dh_sets[x].size)  *low  = ltc_dh_sets[x].size;
       if (*high < ltc_dh_sets[x].size) *high = ltc_dh_sets[x].size;
   }
}

/**
  Returns the DH group size (octets) for given key
  @param key   The DH key to get the size of
  @return The group size in octets (0 on error)
 */
int dh_get_groupsize(dh_key *key)
{
   if (key == NULL) return 0;
   return mp_unsigned_bin_size(key->prime);
}

/**
  Returns the key size for given group size (octets)
  @param groupsize   The DH group size in octets
  @return The key size (0 on error)
*/
int dh_groupsize_to_keysize(int groupsize)
{
   /* The strength estimates from https://tools.ietf.org/html/rfc3526#section-8
    * We use "Estimate 2" to get an appropriate private key (exponent) size.
    */
   if (groupsize <= 0) {
      return 0;
   }
   else if (groupsize <= 192) {
      return 30;     /* 1536-bit => key size 240-bit */
   }
   else if (groupsize <= 256) {
      return 40;     /* 2048-bit => key size 320-bit */
   }
   else if (groupsize <= 384) {
      return 52;     /* 3072-bit => key size 416-bit */
   }
   else if (groupsize <= 512) {
      return 60;     /* 4096-bit => key size 480-bit */
   }
   else if (groupsize <= 768) {
      return 67;     /* 6144-bit => key size 536-bit */
   }
   else if (groupsize <= 1024) {
      return 77;     /* 8192-bit => key size 616-bit */
   }
   else {
      return 0;
   }
}

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
   void *p_minus1;
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
   if ((err = mp_init_multi(&p_minus1, &key->x, &key->y, &key->base, &key->prime, NULL)) != CRYPT_OK) {
      return err;
   }

   /* load the prime and the base */
   if ((err = mp_read_radix(key->base, base_hex, 16)) != CRYPT_OK)   { goto freemp; }
   if ((err = mp_read_radix(key->prime, prime_hex, 16)) != CRYPT_OK) { goto freemp; }
   if ((err = mp_sub_d(key->prime, 1, p_minus1)) != CRYPT_OK)        { goto freemp; }

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

   do {
      /* make up random buf */
      if (prng_descriptor[wprng].read(buf, keysize, prng) != keysize) {
         err = CRYPT_ERROR_READPRNG;
         goto freebuf;
      }
      /* load the x value - private key */
      if ((err = mp_read_unsigned_bin(key->x, buf, keysize)) != CRYPT_OK)  { goto freebuf; }
      /* compute the y value - public key */
      if ((err = mp_exptmod(key->base, key->x, key->prime, key->y)) != CRYPT_OK)            { goto freebuf; }
      /* avoid: y <= 1 OR y >= p-1 */
   } while (mp_cmp(key->y, p_minus1) != LTC_MP_LT || mp_cmp_d(key->y, 1) != LTC_MP_GT);

   /* success */
   key->type = PK_PRIVATE;
   mp_clear_multi(p_minus1, NULL);
   return CRYPT_OK;

freebuf:
   zeromem(buf, keysize);
   XFREE(buf);
freemp:
   mp_clear_multi(p_minus1, key->x, key->y, key->base, key->prime, NULL);
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

/**
  Free the allocated ram for a DH key
  @param key   The key which you wish to free
*/
void dh_free(dh_key *key)
{
   LTC_ARGCHKVD(key != NULL);
   if ( key->base ) {
      mp_clear( key->base );
      key->base = NULL;
   }
   if ( key->prime ) {
      mp_clear( key->prime );
      key->prime = NULL;
   }
   if ( key->x ) {
      mp_clear( key->x );
      key->x = NULL;
   }
   if ( key->y ) {
      mp_clear( key->y );
      key->y = NULL;
   }
}

/**
  Export a DH key to a binary packet
  @param out    [out] The destination for the key
  @param outlen [in/out] The max size and resulting size of the DH key
  @param type   Which type of key (PK_PRIVATE or PK_PUBLIC)
  @param key    The key you wish to export
  @return CRYPT_OK if successful
*/
int dh_export(unsigned char *out, unsigned long *outlen, int type, dh_key *key)
{
   unsigned long y, z;
   int err;

   LTC_ARGCHK(out    != NULL);
   LTC_ARGCHK(outlen != NULL);
   LTC_ARGCHK(key    != NULL);

   /* can we store the static header?  */
   if (*outlen < (PACKET_SIZE + 2)) {
      return CRYPT_BUFFER_OVERFLOW;
   }

   if (type == PK_PRIVATE && key->type != PK_PRIVATE) {
      return CRYPT_PK_NOT_PRIVATE;
   }

   /* header */
   y = PACKET_SIZE;

   /* header */
   out[y++] = type;

   /* export DH group params */
   OUTPUT_BIGNUM(key->prime, out, y, z);
   OUTPUT_BIGNUM(key->base, out, y, z);

   if (type == PK_PRIVATE) {
      /* export x - private key */
      OUTPUT_BIGNUM(key->x, out, y, z);
   }
   else {
      /* export y - public key */
      OUTPUT_BIGNUM(key->y, out, y, z);
   }

   /* store header */
   packet_store_header(out, PACKET_SECT_DH, PACKET_SUB_KEY);

   /* store len */
   *outlen = y;
   return CRYPT_OK;
}

/**
  Import a DH key from a binary packet
  @param in     The packet to read
  @param inlen  The length of the input packet
  @param key    [out] Where to import the key to
  @return CRYPT_OK if successful, on error all allocated memory is freed automatically
*/
int dh_import(const unsigned char *in, unsigned long inlen, dh_key *key)
{
   unsigned long x, y;
   int err;

   LTC_ARGCHK(in  != NULL);
   LTC_ARGCHK(key != NULL);

   /* make sure valid length */
   if ((2+PACKET_SIZE) > inlen) {
      return CRYPT_INVALID_PACKET;
   }

   /* check type byte */
   if ((err = packet_valid_header((unsigned char *)in, PACKET_SECT_DH, PACKET_SUB_KEY)) != CRYPT_OK) {
      return err;
   }

   /* init */
   if ((err = mp_init_multi(&key->prime, &key->base, &key->x, &key->y, NULL)) != CRYPT_OK) {
      return err;
   }

   /* advance past packet header */
   y = PACKET_SIZE;

   /* key type, e.g. private, public */
   key->type = (int)in[y++];

   /* type check both values */
   if ((key->type != PK_PUBLIC) && (key->type != PK_PRIVATE))  {
      err = CRYPT_PK_TYPE_MISMATCH;
      goto error;
   }

   /* load DH group params */
   INPUT_BIGNUM(key->prime, in, x, y, inlen);
   INPUT_BIGNUM(key->base, in, x, y, inlen);

   if (key->type == PK_PRIVATE) {
      /* load private key */
      INPUT_BIGNUM(key->x, in, x, y, inlen);
      /* compute public key */
      if ((err = mp_exptmod(key->base, key->x, key->prime, key->y)) != CRYPT_OK) {
         goto error;
      }
   }
   else {
      /* load public value g^x mod p */
      INPUT_BIGNUM(key->y, in, x, y, inlen);
   }

   return CRYPT_OK;
error:
   mp_clear_multi(key->prime, key->base, key->y, key->x, NULL);
   return err;
}

/**
   Create a DH shared secret.
   @param private_key     The private DH key in the pair
   @param public_key      The public DH key in the pair
   @param out             [out] The destination of the shared data
   @param outlen          [in/out] The max size and resulting size of the shared data.
   @return CRYPT_OK if successful
*/
int dh_shared_secret(dh_key *private_key, dh_key *public_key,
                     unsigned char *out, unsigned long *outlen)
{
   void *tmp;
   unsigned long x;
   int err;

   LTC_ARGCHK(private_key != NULL);
   LTC_ARGCHK(public_key  != NULL);
   LTC_ARGCHK(out         != NULL);
   LTC_ARGCHK(outlen      != NULL);

   /* types valid? */
   if (private_key->type != PK_PRIVATE) {
      return CRYPT_PK_NOT_PRIVATE;
   }

   /* same DH group? */
   if (mp_cmp(private_key->prime, public_key->prime) != LTC_MP_EQ) { return CRYPT_PK_TYPE_MISMATCH; }
   if (mp_cmp(private_key->base, public_key->base) != LTC_MP_EQ)   { return CRYPT_PK_TYPE_MISMATCH; }

   /* init big numbers */
   if ((err = mp_init(&tmp)) != CRYPT_OK) {
      return err;
   }

   /* tmp = p-1 */
   if ((err = mp_sub_d(private_key->prime, 1, tmp)) != CRYPT_OK) {
      goto error;
   }
   /* reject public keys with: y <= 1 OR y >= p-1 */
   if (mp_cmp(public_key->y, tmp) != LTC_MP_LT || mp_cmp_d(public_key->y, 1) != LTC_MP_GT) {
      err = CRYPT_INVALID_ARG;
      goto error;
   }

   /* compute y^x mod p */
   if ((err = mp_exptmod(public_key->y, private_key->x, private_key->prime, tmp)) != CRYPT_OK)  {
      goto error;
   }

   /* enough space for output? */
   x = (unsigned long)mp_unsigned_bin_size(tmp);
   if (*outlen < x) {
      *outlen = x;
      err = CRYPT_BUFFER_OVERFLOW;
      goto error;
   }
   if ((err = mp_to_unsigned_bin(tmp, out)) != CRYPT_OK) {
      goto error;
   }
   *outlen = x;
   err = CRYPT_OK;

error:
   mp_clear(tmp);
   return err;
}

#endif /* LTC_MDH */
