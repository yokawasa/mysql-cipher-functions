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
#include <time.h>
#include <sys/time.h>
#include <mysql.h>
#include <gcrypt.h>
#include "symmetric_key.h"

extern "C" {

/*------------------------------------------------------------------*/
/* cipher: DES                                                      */
/*------------------------------------------------------------------*/
my_bool my_des_encrypt_init(UDF_INIT *initid, UDF_ARGS *args, char *message);
char *my_des_encrypt(UDF_INIT *initid, UDF_ARGS *args, char *result, unsigned long *length, char *is_null, char *error);
void my_des_encrypt_deinit(UDF_INIT *initid);
my_bool my_des_decrypt_init(UDF_INIT *initid, UDF_ARGS *args, char *message);
char *my_des_decrypt(UDF_INIT *initid, UDF_ARGS *args, char *result, unsigned long *length, char *is_null, char *error);
void my_des_decrypt_deinit(UDF_INIT *initid);
/*------------------------------------------------------------------*/
/* cipher: 3DES                                                     */
/*------------------------------------------------------------------*/
my_bool my_3des_encrypt_init(UDF_INIT *initid, UDF_ARGS *args, char *message);
char *my_3des_encrypt(UDF_INIT *initid, UDF_ARGS *args, char *result, unsigned long *length, char *is_null, char *error);
void my_3des_encrypt_deinit(UDF_INIT *initid);
my_bool my_3des_decrypt_init(UDF_INIT *initid, UDF_ARGS *args, char *message);
char *my_3des_decrypt(UDF_INIT *initid, UDF_ARGS *args, char *result, unsigned long *length, char *is_null, char *error);
void my_3des_decrypt_deinit(UDF_INIT *initid);
/*------------------------------------------------------------------*/
/* cipher: AES                                                      */
/*------------------------------------------------------------------*/
my_bool my_aes_encrypt_init(UDF_INIT *initid, UDF_ARGS *args, char *message);
char *my_aes_encrypt(UDF_INIT *initid, UDF_ARGS *args, char *result, unsigned long *length, char *is_null, char *error);
void my_aes_encrypt_deinit(UDF_INIT *initid);
my_bool my_aes_decrypt_init(UDF_INIT *initid, UDF_ARGS *args, char *message);
char *my_aes_decrypt(UDF_INIT *initid, UDF_ARGS *args, char *result, unsigned long *length, char *is_null, char *error);
void my_aes_decrypt_deinit(UDF_INIT *initid);
/*------------------------------------------------------------------*/
/* cipher: AES192                                                   */
/*------------------------------------------------------------------*/
my_bool my_aes192_encrypt_init(UDF_INIT *initid, UDF_ARGS *args, char *message);
char *my_aes192_encrypt(UDF_INIT *initid, UDF_ARGS *args, char *result, unsigned long *length, char *is_null, char *error);
void my_aes192_encrypt_deinit(UDF_INIT *initid);
my_bool my_aes192_decrypt_init(UDF_INIT *initid, UDF_ARGS *args, char *message);
char *my_aes192_decrypt(UDF_INIT *initid, UDF_ARGS *args, char *result, unsigned long *length, char *is_null, char *error);
void my_aes192_decrypt_deinit(UDF_INIT *initid);
/*------------------------------------------------------------------*/
/* cipher: AES256                                                   */
/*------------------------------------------------------------------*/
my_bool my_aes256_encrypt_init(UDF_INIT *initid, UDF_ARGS *args, char *message);
char *my_aes256_encrypt(UDF_INIT *initid, UDF_ARGS *args, char *result, unsigned long *length, char *is_null, char *error);
void my_aes256_encrypt_deinit(UDF_INIT *initid);
my_bool my_aes256_decrypt_init(UDF_INIT *initid, UDF_ARGS *args, char *message);
char *my_aes256_decrypt(UDF_INIT *initid, UDF_ARGS *args, char *result, unsigned long *length, char *is_null, char *error);
void my_aes256_decrypt_deinit(UDF_INIT *initid);

};

int
 get_cipher_mode(const char* str )
{
    if (str == 0 || *str == 0)
        return GCRY_CIPHER_MODE_CBC;

    if ( strcmp(str, "ecb")!=0)
       return GCRY_CIPHER_MODE_ECB;
    else if(strcmp(str, "cbc")!=0)
        return GCRY_CIPHER_MODE_CBC;
    else if(strcmp(str, "cfb")!=0)
        return GCRY_CIPHER_MODE_CFB;
    else if(strcmp(str, "ofb")!=0)
        return GCRY_CIPHER_MODE_OFB;
    else if(strcmp(str, "ctr")!=0)
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
                "Invalid argument %s(): 3rd arg(mode, optional, default cbc) "
                "must be ecb, cbc, cfb, ofb, or ctr", func);
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

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: et sw=4 ts=4 fdm=marker
 * vim<600: et sw=4 ts=4
 */

