/* Copyright 2009 Yoichi Kawasaki
   http://yk55.com

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/
#include <stdio.h>
#include <string.h>
#include <mysql.h>
#include <gcrypt.h>
#include "symmetric_key.h"
#include "message_digest.h"

extern "C" {
// md: MD4
my_bool my_md4_init(UDF_INIT *initid, UDF_ARGS *args, char *message);
char *my_md4(UDF_INIT *initid, UDF_ARGS *args, char *result, unsigned long *length, char *is_null, char *error);
void my_md4_deinit(UDF_INIT *initid);
// md: MD5
my_bool my_md5_init(UDF_INIT *initid, UDF_ARGS *args, char *message);
char *my_md5(UDF_INIT *initid, UDF_ARGS *args, char *result, unsigned long *length, char *is_null, char *error);
void my_md5_deinit(UDF_INIT *initid);
// md: SHA1
my_bool my_sha1_init(UDF_INIT *initid, UDF_ARGS *args, char *message);
char *my_sha1(UDF_INIT *initid, UDF_ARGS *args, char *result, unsigned long *length, char *is_null, char *error);
void my_sha1_deinit(UDF_INIT *initid);
// md: SHA224
my_bool my_sha224_init(UDF_INIT *initid, UDF_ARGS *args, char *message);
char *my_sha224(UDF_INIT *initid, UDF_ARGS *args, char *result, unsigned long *length, char *is_null, char *error);
void my_sha224_deinit(UDF_INIT *initid);
// md: SHA256
my_bool my_sha256_init(UDF_INIT *initid, UDF_ARGS *args, char *message);
char *my_sha256(UDF_INIT *initid, UDF_ARGS *args, char *result, unsigned long *length, char *is_null, char *error);
void my_sha256_deinit(UDF_INIT *initid);
// md: SHA384
my_bool my_sha384_init(UDF_INIT *initid, UDF_ARGS *args, char *message);
char *my_sha384(UDF_INIT *initid, UDF_ARGS *args, char *result, unsigned long *length, char *is_null, char *error);
void my_sha384_deinit(UDF_INIT *initid);
// md: SHA512
my_bool my_sha512_init(UDF_INIT *initid, UDF_ARGS *args, char *message);
char *my_sha512(UDF_INIT *initid, UDF_ARGS *args, char *result, unsigned long *length, char *is_null, char *error);
void my_sha512_deinit(UDF_INIT *initid);
// md: RMD160
my_bool my_rmd160_init(UDF_INIT *initid, UDF_ARGS *args, char *message);
char *my_rmd160(UDF_INIT *initid, UDF_ARGS *args, char *result, unsigned long *length, char *is_null, char *error);
void my_rmd160_deinit(UDF_INIT *initid);
// md: TIGER
my_bool my_tiger_init(UDF_INIT *initid, UDF_ARGS *args, char *message);
char *my_tiger(UDF_INIT *initid, UDF_ARGS *args, char *result, unsigned long *length, char *is_null, char *error);
void my_tiger_deinit(UDF_INIT *initid);
// md: WHIRLPOOL
my_bool my_whirlpool_init(UDF_INIT *initid, UDF_ARGS *args, char *message);
char *my_whirlpool(UDF_INIT *initid, UDF_ARGS *args, char *result, unsigned long *length, char *is_null, char *error);
void my_whirlpool_deinit(UDF_INIT *initid);
// md: CRC32
my_bool my_crc32_init(UDF_INIT *initid, UDF_ARGS *args, char *message);
char *my_crc32(UDF_INIT *initid, UDF_ARGS *args, char *result, unsigned long *length, char *is_null, char *error);
void my_crc32_deinit(UDF_INIT *initid);
// md: CRC32_RFC1510
my_bool my_crc32_rfc1510_init(UDF_INIT *initid, UDF_ARGS *args, char *message);
char *my_crc32_rfc1510(UDF_INIT *initid, UDF_ARGS *args, char *result, unsigned long *length, char *is_null, char *error);
void my_crc32_rfc1510_deinit(UDF_INIT *initid);
// md: CRC24_RFC2440
my_bool my_crc24_rfc2440_init(UDF_INIT *initid, UDF_ARGS *args, char *message);
char *my_crc24_rfc2440(UDF_INIT *initid, UDF_ARGS *args, char *result, unsigned long *length, char *is_null, char *error);
void my_crc24_rfc2440_deinit(UDF_INIT *initid);

// cipher: DES
my_bool my_des_encrypt_init(UDF_INIT *initid, UDF_ARGS *args, char *message);
char *my_des_encrypt(UDF_INIT *initid, UDF_ARGS *args, char *result, unsigned long *length, char *is_null, char *error);
void my_des_encrypt_deinit(UDF_INIT *initid);
my_bool my_des_decrypt_init(UDF_INIT *initid, UDF_ARGS *args, char *message);
char *my_des_decrypt(UDF_INIT *initid, UDF_ARGS *args, char *result, unsigned long *length, char *is_null, char *error);
void my_des_decrypt_deinit(UDF_INIT *initid);
// cipher: 3DES
my_bool my_3des_encrypt_init(UDF_INIT *initid, UDF_ARGS *args, char *message);
char *my_3des_encrypt(UDF_INIT *initid, UDF_ARGS *args, char *result, unsigned long *length, char *is_null, char *error);
void my_3des_encrypt_deinit(UDF_INIT *initid);
my_bool my_3des_decrypt_init(UDF_INIT *initid, UDF_ARGS *args, char *message);
char *my_3des_decrypt(UDF_INIT *initid, UDF_ARGS *args, char *result, unsigned long *length, char *is_null, char *error);
void my_3des_decrypt_deinit(UDF_INIT *initid);
// cipher: AES
my_bool my_aes_encrypt_init(UDF_INIT *initid, UDF_ARGS *args, char *message);
char *my_aes_encrypt(UDF_INIT *initid, UDF_ARGS *args, char *result, unsigned long *length, char *is_null, char *error);
void my_aes_encrypt_deinit(UDF_INIT *initid);
my_bool my_aes_decrypt_init(UDF_INIT *initid, UDF_ARGS *args, char *message);
char *my_aes_decrypt(UDF_INIT *initid, UDF_ARGS *args, char *result, unsigned long *length, char *is_null, char *error);
void my_aes_decrypt_deinit(UDF_INIT *initid);
// cipher: AES192
my_bool my_aes192_encrypt_init(UDF_INIT *initid, UDF_ARGS *args, char *message);
char *my_aes192_encrypt(UDF_INIT *initid, UDF_ARGS *args, char *result, unsigned long *length, char *is_null, char *error);
void my_aes192_encrypt_deinit(UDF_INIT *initid);
my_bool my_aes192_decrypt_init(UDF_INIT *initid, UDF_ARGS *args, char *message);
char *my_aes192_decrypt(UDF_INIT *initid, UDF_ARGS *args, char *result, unsigned long *length, char *is_null, char *error);
void my_aes192_decrypt_deinit(UDF_INIT *initid);
// cipher: AES256
my_bool my_aes256_encrypt_init(UDF_INIT *initid, UDF_ARGS *args, char *message);
char *my_aes256_encrypt(UDF_INIT *initid, UDF_ARGS *args, char *result, unsigned long *length, char *is_null, char *error);
void my_aes256_encrypt_deinit(UDF_INIT *initid);
my_bool my_aes256_decrypt_init(UDF_INIT *initid, UDF_ARGS *args, char *message);
char *my_aes256_decrypt(UDF_INIT *initid, UDF_ARGS *args, char *result, unsigned long *length, char *is_null, char *error);
void my_aes256_decrypt_deinit(UDF_INIT *initid);
// cipher: CAST5
my_bool my_cast5_encrypt_init(UDF_INIT *initid, UDF_ARGS *args, char *message);
char *my_cast5_encrypt(UDF_INIT *initid, UDF_ARGS *args, char *result, unsigned long *length, char *is_null, char *error);
void my_cast5_encrypt_deinit(UDF_INIT *initid);
my_bool my_cast5_decrypt_init(UDF_INIT *initid, UDF_ARGS *args, char *message);
char *my_cast5_decrypt(UDF_INIT *initid, UDF_ARGS *args, char *result, unsigned long *length, char *is_null, char *error);
void my_cast5_decrypt_deinit(UDF_INIT *initid);
// cipher: TWOFISH
my_bool my_twofish_encrypt_init(UDF_INIT *initid, UDF_ARGS *args, char *message);
char *my_twofish_encrypt(UDF_INIT *initid, UDF_ARGS *args, char *result, unsigned long *length, char *is_null, char *error);
void my_twofish_encrypt_deinit(UDF_INIT *initid);
my_bool my_twofish_decrypt_init(UDF_INIT *initid, UDF_ARGS *args, char *message);
char *my_twofish_decrypt(UDF_INIT *initid, UDF_ARGS *args, char *result, unsigned long *length, char *is_null, char *error);
void my_twofish_decrypt_deinit(UDF_INIT *initid);
// cipher: TWOFIS128
my_bool my_twofish128_encrypt_init(UDF_INIT *initid, UDF_ARGS *args, char *message);
char *my_twofish128_encrypt(UDF_INIT *initid, UDF_ARGS *args, char *result, unsigned long *length, char *is_null, char *error);
void my_twofish128_encrypt_deinit(UDF_INIT *initid);
my_bool my_twofish128_decrypt_init(UDF_INIT *initid, UDF_ARGS *args, char *message);
char *my_twofish128_decrypt(UDF_INIT *initid, UDF_ARGS *args, char *result, unsigned long *length, char *is_null, char *error);
void my_twofish128_decrypt_deinit(UDF_INIT *initid);
// cipher: CAMELLIA128
my_bool my_camellia128_encrypt_init(UDF_INIT *initid, UDF_ARGS *args, char *message);
char *my_camellia128_encrypt(UDF_INIT *initid, UDF_ARGS *args, char *result, unsigned long *length, char *is_null, char *error);
void my_camellia128_encrypt_deinit(UDF_INIT *initid);
my_bool my_camellia128_decrypt_init(UDF_INIT *initid, UDF_ARGS *args, char *message);
char *my_camellia128_decrypt(UDF_INIT *initid, UDF_ARGS *args, char *result, unsigned long *length, char *is_null, char *error);
void my_camellia128_decrypt_deinit(UDF_INIT *initid);
// cipher: CAMELLIA192
my_bool my_camellia192_encrypt_init(UDF_INIT *initid, UDF_ARGS *args, char *message);
char *my_camellia192_encrypt(UDF_INIT *initid, UDF_ARGS *args, char *result, unsigned long *length, char *is_null, char *error);
void my_camellia192_encrypt_deinit(UDF_INIT *initid);
my_bool my_camellia192_decrypt_init(UDF_INIT *initid, UDF_ARGS *args, char *message);
char *my_camellia192_decrypt(UDF_INIT *initid, UDF_ARGS *args, char *result, unsigned long *length, char *is_null, char *error);
void my_camellia192_decrypt_deinit(UDF_INIT *initid);
// cipher: CAMELLIA256
my_bool my_camellia256_encrypt_init(UDF_INIT *initid, UDF_ARGS *args, char *message);
char *my_camellia256_encrypt(UDF_INIT *initid, UDF_ARGS *args, char *result, unsigned long *length, char *is_null, char *error);
void my_camellia256_encrypt_deinit(UDF_INIT *initid);
my_bool my_camellia256_decrypt_init(UDF_INIT *initid, UDF_ARGS *args, char *message);
char *my_camellia256_decrypt(UDF_INIT *initid, UDF_ARGS *args, char *result, unsigned long *length, char *is_null, char *error);
void my_camellia256_decrypt_deinit(UDF_INIT *initid);
};

my_bool message_digest_init_common( int algo, const char* func,
                    UDF_INIT *initid, UDF_ARGS *args, char *message)
{
    size_t buflen;
    char *buffer;
    if ( args->arg_count != 1 ) {
        snprintf(message, MYSQL_ERRMSG_SIZE,
            "Invalid argument: %s(<str>).", func);
        return 1;
    }
    args->arg_type[0]=STRING_RESULT;
    initid->maybe_null = 0;
    initid->const_item = 0;
    buflen = cipher::getMessageDigestChecksumBuflen(algo);
    buffer = (char*)malloc(buflen);
    initid->max_length= buflen;
    initid->ptr= buffer;
    return 0;
}

char* message_digest_common( int algo,
            UDF_INIT *initid , UDF_ARGS *args,
             __attribute__ ((unused)) char *result,
            unsigned long *length,
            __attribute__ ((unused)) char *is_null,
            __attribute__ ((unused)) char *error )
{
    char *buffer, *str;
    int mode;
    size_t buflen;
    str  = args->args[0];
    buffer = (char *)initid->ptr;
    buflen = initid->max_length;
    if ( cipher::getMessageDigestChecksum(str, strlen(str), algo, buffer, &buflen) !=0 ) {
        *error = 1; *is_null = 1;
        return NULL;
    }
    *length= buflen;
    return buffer;
}

void message_digest_deinit_common(UDF_INIT *initid) {
    char *buffer = (char *)initid->ptr;
    if (buffer) {
        free(buffer);
    }
}

int
 get_cipher_mode(const char* str )
{
    if (str == 0 || *str == 0)
        return GCRY_CIPHER_MODE_CBC;

    if ( strcmp(str, "ecb")==0)
       return GCRY_CIPHER_MODE_ECB;
    else if(strcmp(str, "cbc")==0)
        return GCRY_CIPHER_MODE_CBC;
    else if(strcmp(str, "cfb")==0)
        return GCRY_CIPHER_MODE_CFB;
    else if(strcmp(str, "ofb")==0)
        return GCRY_CIPHER_MODE_OFB;
    else if(strcmp(str, "ctr")==0)
        return GCRY_CIPHER_MODE_CTR;

    return GCRY_CIPHER_MODE_CBC;
}

my_bool symmetric_key_init_common(const char* func, UDF_INIT *initid, UDF_ARGS *args, char *message)
{
    size_t buflen;
    char *buffer;
    if ( args->arg_count < 2 || args->arg_count > 4 ) {
        snprintf(message, MYSQL_ERRMSG_SIZE,
            "Invalid argument: %s(<str>,<key>[,<mode>][,<iv>|<ctr>]).", func);
        return 1;
    }
    if ( args->arg_count > 1) {
        args->arg_type[0]=STRING_RESULT;
        args->arg_type[1]=STRING_RESULT;
    }
    if ( args->arg_count > 2) {
        args->arg_type[2]=STRING_RESULT;
        if ( strcmp(args->args[2], "ecb")!=0
          && strcmp(args->args[2], "cbc")!=0
          && strcmp(args->args[2], "cfb")!=0
          && strcmp(args->args[2], "ofb")!=0
          && strcmp(args->args[2], "ctr")!=0
        ) {
            snprintf(message, MYSQL_ERRMSG_SIZE,
                "Invalid argument %s(): 3rd arg(optional) is block mode : "
                "ecb|cbc|cfb|ofb|ctr and default cbc.", func);
            return 1;
        }
    }
    if ( args->arg_count > 3 )
        args->arg_type[3]!=STRING_RESULT;

    // should set maybe_null to 1 if the handler can return NULL.
    initid->maybe_null = 0;
    // should set const_item to 1 if the handler always returns the same value
    // and to 0 otherwise
    initid->const_item = 0;

    // An argument of type STRING_RESULT  is given as a string pointer plus a length,
    // to allow handling of binary data or data of arbitrary length. The string contents
    // are available as args->args[i] and the string length is args->lengths[i].
    // Do not assume that the string is null-terminated.
    // That is, do not use strlen to obtain arument length.
    buflen = cipher::SymmetricKey::getEncryptBuflen(GCRY_CIPHER_AES, args->lengths[0]);
    buffer = (char*)malloc(buflen);
    // The maximum length of the result.
    initid->max_length= buflen;
    // A pointer that the function can use for its own purposes
    initid->ptr= buffer;
    return 0;
}

char* symmetric_key_encrypt_common( int algo,
            UDF_INIT *initid , UDF_ARGS *args,
             __attribute__ ((unused)) char *result,
            unsigned long *length,
            __attribute__ ((unused)) char *is_null,
            __attribute__ ((unused)) char *error )
{
    char *buffer, *str, *key, *iv, *ctr;
    int mode;
    size_t buflen;
    buffer = (char *)initid->ptr;
    buflen = initid->max_length;
    str  = args->args[0];
    key  = args->args[1];
    mode = (args->arg_count > 2) ? get_cipher_mode(args->args[2]) : get_cipher_mode(NULL);

    if (mode == GCRY_CIPHER_MODE_CBC
      || mode == GCRY_CIPHER_MODE_CFB
      || mode == GCRY_CIPHER_MODE_OFB ) {
        iv = (args->arg_count > 3) ? args->args[3] : NULL;
    } else {
        iv = NULL;
    }
    ctr =  (mode == GCRY_CIPHER_MODE_CTR && args->arg_count > 3 ) ? args->args[3] : NULL;

    cipher::SymmetricKey sym(algo, mode);
    if ( sym.setKey(key) !=0 ) {
        *error = 1; *is_null = 1;
        return NULL;
    }
    if ( sym.setKey(key) !=0 ) {
        *error = 1; *is_null = 1;
        return NULL;
    }
    if ( mode != GCRY_CIPHER_MODE_CTR ) {
        if ( sym.setIV(iv) !=0 ) {
            *error = 1; *is_null = 1;
            return NULL;
        }
    }
    else {
        if ( sym.setCtr(ctr) !=0 ) {
            *error = 1; *is_null = 1;
            return NULL;
        }
    }

    if (sym.encrypt(buffer, buflen, args->args[0], strlen(args->args[0])) != 0 ) {
        *error = 1; *is_null = 1;
        return NULL;
    }
    *length= buflen;
    return buffer;
}

char* symmetric_key_decrypt_common( int algo,
            UDF_INIT *initid , UDF_ARGS *args,
             __attribute__ ((unused)) char *result,
            unsigned long *length,
            __attribute__ ((unused)) char *is_null,
            __attribute__ ((unused)) char *error )
{
    char *buffer, *str, *key, *iv, *ctr;
    int mode;
    size_t buflen;
    buffer = (char *)initid->ptr;
    buflen = initid->max_length;
    str  = args->args[0];
    key  = args->args[1];
    mode = (args->arg_count > 2) ? get_cipher_mode(args->args[2]) : get_cipher_mode(NULL);

    if (mode == GCRY_CIPHER_MODE_CBC
      || mode == GCRY_CIPHER_MODE_CFB
      || mode == GCRY_CIPHER_MODE_OFB ) {
        iv = (args->arg_count > 3) ? args->args[3] : NULL;
    } else {
        iv = NULL;
    }
    ctr =  (mode == GCRY_CIPHER_MODE_CTR && args->arg_count > 3 ) ? args->args[3] : NULL;

    cipher::SymmetricKey sym(algo, mode);
    if ( sym.setKey(key) !=0 ) {
        *error = 1; *is_null = 1;
        return NULL;
    }
    if ( sym.setKey(key) !=0 ) {
        *error = 1; *is_null = 1;
        return NULL;
    }
    if ( mode != GCRY_CIPHER_MODE_CTR ) {
        if ( sym.setIV(iv) !=0 ) {
            *error = 1; *is_null = 1;
            return NULL;
        }
    }
    else {
        if ( sym.setCtr(ctr) !=0 ) {
            *error = 1; *is_null = 1;
            return NULL;
        }
    }

    if (sym.decrypt(buffer, buflen, args->args[0], buflen) != 0 ) {
        *error = 1; *is_null = 1;
        return NULL;
    }
    *length= buflen;
    return buffer;
}

void symmetric_key_deinit_common(UDF_INIT *initid) {
    char *buffer = (char *)initid->ptr;
    if (buffer) {
        free(buffer);
    }
}


/*------------------------------------------------------------------*/
/* md: MD4                                                          */
/*------------------------------------------------------------------*/
my_bool my_md4_init(UDF_INIT *initid, UDF_ARGS *args, char *message)
{
    return message_digest_init_common(GCRY_MD_MD4, "my_md4", initid, args, message);
}
char *my_md4(UDF_INIT *initid, UDF_ARGS *args, char *result, unsigned long *length, char *is_null, char *error)
{
    return message_digest_common(GCRY_MD_MD4, initid, args, result, length, is_null, error);
}
void my_md4_deinit(UDF_INIT *initid)
{
    message_digest_deinit_common(initid);
}

/*------------------------------------------------------------------*/
/* md: MD5                                                          */
/*------------------------------------------------------------------*/
my_bool my_md5_init(UDF_INIT *initid, UDF_ARGS *args, char *message)
{
    return message_digest_init_common(GCRY_MD_MD5, "my_md5", initid, args, message);
}
char *my_md5(UDF_INIT *initid, UDF_ARGS *args, char *result, unsigned long *length, char *is_null, char *error)
{
    return message_digest_common(GCRY_MD_MD5, initid, args, result, length, is_null, error);
}
void my_md5_deinit(UDF_INIT *initid)
{
    message_digest_deinit_common(initid);
}

/*------------------------------------------------------------------*/
/* md: SHA1                                                         */
/*------------------------------------------------------------------*/
my_bool my_sha1_init(UDF_INIT *initid, UDF_ARGS *args, char *message)
{
    return message_digest_init_common(GCRY_MD_SHA1, "my_sha1", initid, args, message);
}
char *my_sha1(UDF_INIT *initid, UDF_ARGS *args, char *result, unsigned long *length, char *is_null, char *error)
{
    return message_digest_common(GCRY_MD_SHA1, initid, args, result, length, is_null, error);
}
void my_sha1_deinit(UDF_INIT *initid)
{
    message_digest_deinit_common(initid);
}

/*------------------------------------------------------------------*/
/* md: SHA224                                                       */
/*------------------------------------------------------------------*/
my_bool my_sha224_init(UDF_INIT *initid, UDF_ARGS *args, char *message)
{
    return message_digest_init_common(GCRY_MD_SHA224, "my_sha224", initid, args, message);
}
char *my_sha224(UDF_INIT *initid, UDF_ARGS *args, char *result, unsigned long *length, char *is_null, char *error)
{
    return message_digest_common(GCRY_MD_SHA224, initid, args, result, length, is_null, error);
}
void my_sha224_deinit(UDF_INIT *initid)
{
    message_digest_deinit_common(initid);
}

/*------------------------------------------------------------------*/
/* md: SHA256                                                       */
/*------------------------------------------------------------------*/
my_bool my_sha256_init(UDF_INIT *initid, UDF_ARGS *args, char *message)
{
    return message_digest_init_common(GCRY_MD_SHA256, "my_sha256", initid, args, message);
}
char *my_sha256(UDF_INIT *initid, UDF_ARGS *args, char *result, unsigned long *length, char *is_null, char *error)
{
    return message_digest_common(GCRY_MD_SHA256, initid, args, result, length, is_null, error);
}
void my_sha256_deinit(UDF_INIT *initid)
{
    message_digest_deinit_common(initid);
}

/*------------------------------------------------------------------*/
/* md: SHA384                                                       */
/*------------------------------------------------------------------*/
my_bool my_sha384_init(UDF_INIT *initid, UDF_ARGS *args, char *message)
{
    return message_digest_init_common(GCRY_MD_SHA384, "my_sha384", initid, args, message);
}
char *my_sha384(UDF_INIT *initid, UDF_ARGS *args, char *result, unsigned long *length, char *is_null, char *error)
{
    return message_digest_common(GCRY_MD_SHA384, initid, args, result, length, is_null, error);
}
void my_sha384_deinit(UDF_INIT *initid)
{
    message_digest_deinit_common(initid);
}

/*------------------------------------------------------------------*/
/* md: SHA512                                                       */
/*------------------------------------------------------------------*/
my_bool my_sha512_init(UDF_INIT *initid, UDF_ARGS *args, char *message)
{
    return message_digest_init_common(GCRY_MD_SHA512, "my_sha512", initid, args, message);
}
char *my_sha512(UDF_INIT *initid, UDF_ARGS *args, char *result, unsigned long *length, char *is_null, char *error)
{
    return message_digest_common(GCRY_MD_SHA512, initid, args, result, length, is_null, error);
}
void my_sha512_deinit(UDF_INIT *initid)
{
    message_digest_deinit_common(initid);
}

/*------------------------------------------------------------------*/
/* md: RMD160                                                       */
/*------------------------------------------------------------------*/
my_bool my_rmd160_init(UDF_INIT *initid, UDF_ARGS *args, char *message)
{
    return message_digest_init_common(GCRY_MD_RMD160, "my_rmd160", initid, args, message);
}
char *my_rmd160(UDF_INIT *initid, UDF_ARGS *args, char *result, unsigned long *length, char *is_null, char *error)
{
    return message_digest_common(GCRY_MD_RMD160, initid, args, result, length, is_null, error);
}
void my_rmd160_deinit(UDF_INIT *initid)
{
    message_digest_deinit_common(initid);
}

/*------------------------------------------------------------------*/
/* md: TIGER                                                        */
/*------------------------------------------------------------------*/
my_bool my_tiger_init(UDF_INIT *initid, UDF_ARGS *args, char *message)
{
    return message_digest_init_common(GCRY_MD_TIGER, "my_tiger", initid, args, message);
}
char *my_tiger(UDF_INIT *initid, UDF_ARGS *args, char *result, unsigned long *length, char *is_null, char *error)
{
    return message_digest_common(GCRY_MD_TIGER, initid, args, result, length, is_null, error);
}
void my_tiger_deinit(UDF_INIT *initid)
{
    message_digest_deinit_common(initid);
}

/*------------------------------------------------------------------*/
/* md: WHIRLPOOL                                                    */
/*------------------------------------------------------------------*/
my_bool my_whirlpool_init(UDF_INIT *initid, UDF_ARGS *args, char *message)
{
    return message_digest_init_common(GCRY_MD_WHIRLPOOL, "my_whirlpool", initid, args, message);
}
char *my_whirlpool(UDF_INIT *initid, UDF_ARGS *args, char *result, unsigned long *length, char *is_null, char *error)
{
    return message_digest_common(GCRY_MD_WHIRLPOOL, initid, args, result, length, is_null, error);
}
void my_whirlpool_deinit(UDF_INIT *initid)
{
    message_digest_deinit_common(initid);
}

/*------------------------------------------------------------------*/
/* md: CRC32                                                        */
/*------------------------------------------------------------------*/
my_bool my_crc32_init(UDF_INIT *initid, UDF_ARGS *args, char *message)
{
    return message_digest_init_common(GCRY_MD_CRC32, "my_crc32", initid, args, message);
}
char *my_crc32(UDF_INIT *initid, UDF_ARGS *args, char *result, unsigned long *length, char *is_null, char *error)
{
    return message_digest_common(GCRY_MD_CRC32, initid, args, result, length, is_null, error);
}
void my_crc32_deinit(UDF_INIT *initid)
{
    message_digest_deinit_common(initid);
}

/*------------------------------------------------------------------*/
/* md: CRC32_RFC1510                                                */
/*------------------------------------------------------------------*/
my_bool my_crc32_rfc1510_init(UDF_INIT *initid, UDF_ARGS *args, char *message)
{
    return message_digest_init_common(GCRY_MD_CRC32_RFC1510, "my_crc32_rfc1510", initid, args, message);
}
char *my_crc32_rfc1510(UDF_INIT *initid, UDF_ARGS *args, char *result, unsigned long *length, char *is_null, char *error)
{
    return message_digest_common(GCRY_MD_CRC32_RFC1510, initid, args, result, length, is_null, error);
}
void my_crc32_rfc1510_deinit(UDF_INIT *initid)
{
    message_digest_deinit_common(initid);
}

/*------------------------------------------------------------------*/
/* md: CRC24_RFC2440                                                */
/*------------------------------------------------------------------*/
my_bool my_crc24_rfc2440_init(UDF_INIT *initid, UDF_ARGS *args, char *message)
{
    return message_digest_init_common(GCRY_MD_CRC24_RFC2440, "my_crc24_rfc2440", initid, args, message);
}
char *my_crc24_rfc2440(UDF_INIT *initid, UDF_ARGS *args, char *result, unsigned long *length, char *is_null, char *error)
{
    return message_digest_common(GCRY_MD_CRC24_RFC2440, initid, args, result, length, is_null, error);
}
void my_crc24_rfc2440_deinit(UDF_INIT *initid)
{
    message_digest_deinit_common(initid);
}

/*------------------------------------------------------------------*/
/* cipher: DES                                                      */
/*------------------------------------------------------------------*/
my_bool my_des_encrypt_init(UDF_INIT *initid, UDF_ARGS *args, char *message)
{
    return symmetric_key_init_common("my_des_encrypt", initid, args, message);
}
char* my_des_encrypt(UDF_INIT *initid , UDF_ARGS *args, char *result, unsigned long *length, char *is_null, char *error)
{
    return symmetric_key_encrypt_common(GCRY_CIPHER_DES, initid, args, result, length, is_null, error);
}
void my_des_encrypt_deinit(UDF_INIT *initid)
{
    symmetric_key_deinit_common(initid);
}
my_bool my_des_decrypt_init(UDF_INIT *initid, UDF_ARGS *args, char *message)
{
    return symmetric_key_init_common("my_des_decrypt", initid, args, message);
}
char* my_des_decrypt(UDF_INIT *initid , UDF_ARGS *args, char *result, unsigned long *length, char *is_null, char *error)
{
    return symmetric_key_decrypt_common(GCRY_CIPHER_DES, initid, args, result, length, is_null, error);
}
void my_des_decrypt_deinit(UDF_INIT *initid)
{
    symmetric_key_deinit_common(initid);
}

/*------------------------------------------------------------------*/
/* cipher: 3DES                                                     */
/*------------------------------------------------------------------*/
my_bool my_3des_encrypt_init(UDF_INIT *initid, UDF_ARGS *args, char *message)
{
    return symmetric_key_init_common("my_3des_encrypt", initid, args, message);
}
char* my_3des_encrypt(UDF_INIT *initid , UDF_ARGS *args, char *result, unsigned long *length, char *is_null, char *error)
{
    return symmetric_key_encrypt_common(GCRY_CIPHER_3DES, initid, args, result, length, is_null, error);
}
void my_3des_encrypt_deinit(UDF_INIT *initid)
{
    symmetric_key_deinit_common(initid);
}
my_bool my_3des_decrypt_init(UDF_INIT *initid, UDF_ARGS *args, char *message)
{
    return symmetric_key_init_common("my_3des_decrypt", initid, args, message);
}
char* my_3des_decrypt(UDF_INIT *initid , UDF_ARGS *args, char *result, unsigned long *length, char *is_null, char *error)
{
    return symmetric_key_decrypt_common(GCRY_CIPHER_3DES, initid, args, result, length, is_null, error);
}
void my_3des_decrypt_deinit(UDF_INIT *initid)
{
    symmetric_key_deinit_common(initid);
}

/*------------------------------------------------------------------*/
/* cipher: AES                                                      */
/*------------------------------------------------------------------*/
my_bool my_aes_encrypt_init(UDF_INIT *initid, UDF_ARGS *args, char *message)
{
    return symmetric_key_init_common("my_aes_encrypt", initid, args, message);
}
char* my_aes_encrypt(UDF_INIT *initid , UDF_ARGS *args, char *result, unsigned long *length, char *is_null, char *error)
{
    return symmetric_key_encrypt_common(GCRY_CIPHER_AES, initid, args, result, length, is_null, error);
}
void my_aes_encrypt_deinit(UDF_INIT *initid)
{
    symmetric_key_deinit_common(initid);
}
my_bool my_aes_decrypt_init(UDF_INIT *initid, UDF_ARGS *args, char *message)
{
    return symmetric_key_init_common("my_aes_decrypt", initid, args, message);
}
char* my_aes_decrypt(UDF_INIT *initid , UDF_ARGS *args, char *result, unsigned long *length, char *is_null, char *error)
{
    return symmetric_key_decrypt_common(GCRY_CIPHER_AES, initid, args, result, length, is_null, error);
}
void my_aes_decrypt_deinit(UDF_INIT *initid)
{
    symmetric_key_deinit_common(initid);
}

/*------------------------------------------------------------------*/
/* cipher: AES192                                                   */
/*------------------------------------------------------------------*/
my_bool my_aes192_encrypt_init(UDF_INIT *initid, UDF_ARGS *args, char *message)
{
    return symmetric_key_init_common("my_aes192_encrypt", initid, args, message);
}
char* my_aes192_encrypt(UDF_INIT *initid , UDF_ARGS *args, char *result, unsigned long *length, char *is_null, char *error)
{
    return symmetric_key_encrypt_common(GCRY_CIPHER_AES192, initid, args, result, length, is_null, error);
}
void my_aes192_encrypt_deinit(UDF_INIT *initid)
{
    symmetric_key_deinit_common(initid);
}
my_bool my_aes192_decrypt_init(UDF_INIT *initid, UDF_ARGS *args, char *message)
{
    return symmetric_key_init_common("my_aes192_decrypt", initid, args, message);
}
char* my_aes192_decrypt(UDF_INIT *initid , UDF_ARGS *args, char *result, unsigned long *length, char *is_null, char *error)
{
    return symmetric_key_decrypt_common(GCRY_CIPHER_AES192, initid, args, result, length, is_null, error);
}
void my_aes192_decrypt_deinit(UDF_INIT *initid)
{
    symmetric_key_deinit_common(initid);
}

/*------------------------------------------------------------------*/
/* cipher: AES256                                                   */
/*------------------------------------------------------------------*/
my_bool my_aes256_encrypt_init(UDF_INIT *initid, UDF_ARGS *args, char *message)
{
    return symmetric_key_init_common("my_aes256_encrypt", initid, args, message);
}
char* my_aes256_encrypt(UDF_INIT *initid , UDF_ARGS *args, char *result, unsigned long *length, char *is_null, char *error)
{
    return symmetric_key_encrypt_common(GCRY_CIPHER_AES256, initid, args, result, length, is_null, error);
}
void my_aes256_encrypt_deinit(UDF_INIT *initid)
{
    symmetric_key_deinit_common(initid);
}
my_bool my_aes256_decrypt_init(UDF_INIT *initid, UDF_ARGS *args, char *message)
{
    return symmetric_key_init_common("my_aes256_decrypt", initid, args, message);
}
char* my_aes256_decrypt(UDF_INIT *initid , UDF_ARGS *args, char *result, unsigned long *length, char *is_null, char *error)
{
    return symmetric_key_decrypt_common(GCRY_CIPHER_AES256, initid, args, result, length, is_null, error);
}
void my_aes256_decrypt_deinit(UDF_INIT *initid)
{
    symmetric_key_deinit_common(initid);
}

/*------------------------------------------------------------------*/
/* cipher: CAST5                                                    */
/*------------------------------------------------------------------*/
my_bool my_cast5_encrypt_init(UDF_INIT *initid, UDF_ARGS *args, char *message)
{
    return symmetric_key_init_common("my_cast5_encrypt", initid, args, message);
}
char* my_cast5_encrypt(UDF_INIT *initid , UDF_ARGS *args, char *result, unsigned long *length, char *is_null, char *error)
{
    return symmetric_key_encrypt_common(GCRY_CIPHER_CAST5, initid, args, result, length, is_null, error);
}
void my_cast5_encrypt_deinit(UDF_INIT *initid)
{
    symmetric_key_deinit_common(initid);
}
my_bool my_cast5_decrypt_init(UDF_INIT *initid, UDF_ARGS *args, char *message)
{
    return symmetric_key_init_common("my_cast5_decrypt", initid, args, message);
}
char* my_cast5_decrypt(UDF_INIT *initid , UDF_ARGS *args, char *result, unsigned long *length, char *is_null, char *error)
{
    return symmetric_key_decrypt_common(GCRY_CIPHER_CAST5, initid, args, result, length, is_null, error);
}
void my_cast5_decrypt_deinit(UDF_INIT *initid)
{
    symmetric_key_deinit_common(initid);
}

/*------------------------------------------------------------------*/
/* cipher: TWOFISH                                                  */
/*------------------------------------------------------------------*/
my_bool my_twofish_encrypt_init(UDF_INIT *initid, UDF_ARGS *args, char *message)
{
    return symmetric_key_init_common("my_twofish_encrypt", initid, args, message);
}
char* my_twofish_encrypt(UDF_INIT *initid , UDF_ARGS *args, char *result, unsigned long *length, char *is_null, char *error)
{
    return symmetric_key_encrypt_common(GCRY_CIPHER_TWOFISH, initid, args, result, length, is_null, error);
}
void my_twofish_encrypt_deinit(UDF_INIT *initid)
{
    symmetric_key_deinit_common(initid);
}
my_bool my_twofish_decrypt_init(UDF_INIT *initid, UDF_ARGS *args, char *message)
{
    return symmetric_key_init_common("my_twofish_decrypt", initid, args, message);
}
char* my_twofish_decrypt(UDF_INIT *initid , UDF_ARGS *args, char *result, unsigned long *length, char *is_null, char *error)
{
    return symmetric_key_decrypt_common(GCRY_CIPHER_TWOFISH, initid, args, result, length, is_null, error);
}
void my_twofish_decrypt_deinit(UDF_INIT *initid)
{
    symmetric_key_deinit_common(initid);
}

/*------------------------------------------------------------------*/
/* cipher: TWOFISH128                                               */
/*------------------------------------------------------------------*/
my_bool my_twofish128_encrypt_init(UDF_INIT *initid, UDF_ARGS *args, char *message)
{
    return symmetric_key_init_common("my_twofish128_encrypt", initid, args, message);
}
char* my_twofish128_encrypt(UDF_INIT *initid , UDF_ARGS *args, char *result, unsigned long *length, char *is_null, char *error)
{
    return symmetric_key_encrypt_common(GCRY_CIPHER_TWOFISH128, initid, args, result, length, is_null, error);
}
void my_twofish128_encrypt_deinit(UDF_INIT *initid)
{
    symmetric_key_deinit_common(initid);
}
my_bool my_twofish128_decrypt_init(UDF_INIT *initid, UDF_ARGS *args, char *message)
{
    return symmetric_key_init_common("my_twofish128_decrypt", initid, args, message);
}
char* my_twofish128_decrypt(UDF_INIT *initid , UDF_ARGS *args, char *result, unsigned long *length, char *is_null, char *error)
{
    return symmetric_key_decrypt_common(GCRY_CIPHER_TWOFISH128, initid, args, result, length, is_null, error);
}
void my_twofish128_decrypt_deinit(UDF_INIT *initid)
{
    symmetric_key_deinit_common(initid);
}

/*------------------------------------------------------------------*/
/* cipher: CAMELLIA128                                              */
/*------------------------------------------------------------------*/
my_bool my_camellia128_encrypt_init(UDF_INIT *initid, UDF_ARGS *args, char *message)
{
    return symmetric_key_init_common("my_camellia128_encrypt", initid, args, message);
}
char* my_camellia128_encrypt(UDF_INIT *initid , UDF_ARGS *args, char *result, unsigned long *length, char *is_null, char *error)
{
    return symmetric_key_encrypt_common(GCRY_CIPHER_CAMELLIA128, initid, args, result, length, is_null, error);
}
void my_camellia128_encrypt_deinit(UDF_INIT *initid)
{
    symmetric_key_deinit_common(initid);
}
my_bool my_camellia128_decrypt_init(UDF_INIT *initid, UDF_ARGS *args, char *message)
{
    return symmetric_key_init_common("my_camellia128_decrypt", initid, args, message);
}
char* my_camellia128_decrypt(UDF_INIT *initid , UDF_ARGS *args, char *result, unsigned long *length, char *is_null, char *error)
{
    return symmetric_key_decrypt_common(GCRY_CIPHER_CAMELLIA128, initid, args, result, length, is_null, error);
}
void my_camellia128_decrypt_deinit(UDF_INIT *initid)
{
    symmetric_key_deinit_common(initid);
}

/*------------------------------------------------------------------*/
/* cipher: CAMELLIA192                                              */
/*------------------------------------------------------------------*/
my_bool my_camellia192_encrypt_init(UDF_INIT *initid, UDF_ARGS *args, char *message)
{
    return symmetric_key_init_common("my_camellia192_encrypt", initid, args, message);
}
char* my_camellia192_encrypt(UDF_INIT *initid , UDF_ARGS *args, char *result, unsigned long *length, char *is_null, char *error)
{
    return symmetric_key_encrypt_common(GCRY_CIPHER_CAMELLIA192, initid, args, result, length, is_null, error);
}
void my_camellia192_encrypt_deinit(UDF_INIT *initid)
{
    symmetric_key_deinit_common(initid);
}
my_bool my_camellia192_decrypt_init(UDF_INIT *initid, UDF_ARGS *args, char *message)
{
    return symmetric_key_init_common("my_camellia192_decrypt", initid, args, message);
}
char* my_camellia192_decrypt(UDF_INIT *initid , UDF_ARGS *args, char *result, unsigned long *length, char *is_null, char *error)
{
    return symmetric_key_decrypt_common(GCRY_CIPHER_CAMELLIA192, initid, args, result, length, is_null, error);
}
void my_camellia192_decrypt_deinit(UDF_INIT *initid)
{
    symmetric_key_deinit_common(initid);
}

/*------------------------------------------------------------------*/
/* cipher: CAMELLIA256                                              */
/*------------------------------------------------------------------*/
my_bool my_camellia256_encrypt_init(UDF_INIT *initid, UDF_ARGS *args, char *message)
{
    return symmetric_key_init_common("my_camellia256_encrypt", initid, args, message);
}
char* my_camellia256_encrypt(UDF_INIT *initid , UDF_ARGS *args, char *result, unsigned long *length, char *is_null, char *error)
{
    return symmetric_key_encrypt_common(GCRY_CIPHER_CAMELLIA256, initid, args, result, length, is_null, error);
}
void my_camellia256_encrypt_deinit(UDF_INIT *initid)
{
    symmetric_key_deinit_common(initid);
}
my_bool my_camellia256_decrypt_init(UDF_INIT *initid, UDF_ARGS *args, char *message)
{
    return symmetric_key_init_common("my_camellia256_decrypt", initid, args, message);
}
char* my_camellia256_decrypt(UDF_INIT *initid , UDF_ARGS *args, char *result, unsigned long *length, char *is_null, char *error)
{
    return symmetric_key_decrypt_common(GCRY_CIPHER_CAMELLIA256, initid, args, result, length, is_null, error);
}
void my_camellia256_decrypt_deinit(UDF_INIT *initid)
{
    symmetric_key_deinit_common(initid);
}

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: et sw=4 ts=4 fdm=marker
 * vim<600: et sw=4 ts=4
 */

