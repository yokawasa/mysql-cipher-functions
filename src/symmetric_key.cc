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
#include <gcrypt.h>
#include "symmetric_key.h"

namespace cipher
{

struct gc_sym_s {
    int mode;
    int algo;
    gcry_cipher_hd_t h;
    gcry_error_t err;
    size_t blklen;
    size_t keylen;
};
typedef struct gc_sym_s GCSYM;

class SymmetricKeyPrivate {
 public:
    SymmetricKeyPrivate() {
        initialized = 0;
        gcs = NULL;
    }
    ~SymmetricKeyPrivate() {
    }
    int initialized;
    GCSYM *gcs;
};

SymmetricKey::
 SymmetricKey(int algo, int mode) {
    this->dp = std::auto_ptr<SymmetricKeyPrivate>(new SymmetricKeyPrivate);
    if (this->initRes(algo, mode)==0) {
        this->dp->initialized = 1;
    }
}

SymmetricKey::
 ~SymmetricKey() {
    this->freeRes();
}

int
SymmetricKey::
 setIV(const char *ivbuf){
    size_t ivlen;
    char *iv;
    if (!this->dp->initialized) {
        return 1;
    }
    iv = (char*)gcry_malloc(this->dp->gcs->blklen);
    if (ivbuf) {
        ivlen = strlen(ivbuf);
        if (ivlen > this->dp->gcs->blklen) {
            ivlen = this->dp->gcs->blklen;
        }
        memcpy(iv, ivbuf, ivlen);
    } else {
        ivlen = 0;
    }
    memset(iv + ivlen, 0, this->dp->gcs->blklen - ivlen);
    this->dp->gcs->err = gcry_cipher_setiv(this->dp->gcs->h, iv, this->dp->gcs->blklen);
    gcry_free(iv);
    if (this->dp->gcs->err != 0) {
        fprintf(stderr, "setiv failure: %s\n", gcry_strerror(this->dp->gcs->err) );
    }
    return this->dp->gcs->err;
}

int
SymmetricKey::
 setKey(const char *keybuf) {
    char *k;
    size_t keylen;
    if (!this->dp->initialized) {
        return 1;
    }
    k = (char*)gcry_malloc(this->dp->gcs->keylen);
    keylen = strlen(keybuf);
    if ( keylen >= this->dp->gcs->keylen ) {
        memcpy(k, keybuf, this->dp->gcs->keylen);
    } else {
        // If key is shorter than the algorithm's key size
        // let's pad it with zeroes
        memcpy(k, keybuf, keylen);
        memset(k + keylen, 0, this->dp->gcs->keylen - keylen);
    }
    this->dp->gcs->err = gcry_cipher_setkey(this->dp->gcs->h, k,  this->dp->gcs->keylen);
    gcry_free(k);
    if (this->dp->gcs->err != 0) {
        fprintf(stderr, "setkey failure: %s\n", gcry_strerror(this->dp->gcs->err) );
    }
    return this->dp->gcs->err;
}

int
SymmetricKey::
 setCtr(const char *ctrbuf) {
    size_t ctrlen;
    char *ctr;
    if (!this->dp->initialized) {
        return 1;
    }
    ctr = (char*)gcry_malloc(this->dp->gcs->blklen);
    if (ctrbuf) {
        ctrlen = strlen(ctrbuf);
        if (ctrlen > this->dp->gcs->blklen) {
            ctrlen = this->dp->gcs->blklen;
        }
        memcpy(ctr, ctrbuf, ctrlen);
    } else {
        ctrlen = 0;
    }
    memset(ctr + ctrlen, 0, this->dp->gcs->blklen - ctrlen);
    this->dp->gcs->err = gcry_cipher_setctr(this->dp->gcs->h, ctr, this->dp->gcs->blklen);
    gcry_free(ctr);
    if (this->dp->gcs->err != 0) {
        fprintf(stderr, "setiv failure: %s\n", gcry_strerror(this->dp->gcs->err) );
    }
    return this->dp->gcs->err;
}

size_t
SymmetricKey::
 getEncryptBuflen(size_t inlen) const {
    if (!this->dp->initialized) {
        return 0; // return 0 no matter what
    }
    size_t l =0;
    size_t tmpl =0;
    if (inlen > 0) {
        l = inlen;
        tmpl = l;
        if (l > this->dp->gcs->blklen) {
            tmpl = ( l / this->dp->gcs->blklen) * this->dp->gcs->blklen;
            if (l % this->dp->gcs->blklen) {
                tmpl += this->dp->gcs->blklen;
            }
            l = tmpl;
        } else {
            l = this->dp->gcs->blklen;
        }
    }
    return l;
}

size_t
SymmetricKey::
 getEncryptBuflen(int algo, size_t inlen) {
    size_t l, tmpl, blklen, keylen;
    l =0;
    tmpl =0;
    blklen = (size_t)gcry_cipher_get_algo_blklen(algo);
    keylen = (size_t)gcry_cipher_get_algo_keylen(algo);
    if (inlen > 0) {
        l = inlen;
        tmpl = l;
        if (l > blklen) {
            tmpl = ( l / blklen) * blklen;
            if (l % blklen) {
                tmpl += blklen;
            }
            l = tmpl;
        } else {
            l = blklen;
        }
    }
    return l;
}

int
SymmetricKey::
 encrypt(char *outbuf, size_t outlen, const char *inbuf, size_t inlen) {
    char *curbuf;
    if (!this->dp->initialized) {
        return 1;
    }
    if (!inbuf || inlen < 1) {
        fprintf(stderr, "encrypt invalid param: nbuf is null or empty\n");
        return 1;
    }
    curbuf = (char*)gcry_malloc(outlen);
    memcpy(curbuf, inbuf, inlen);
    if (outlen > inlen) {
        memset(curbuf + inlen, 0, outlen - inlen);
    }
    if (inlen > 0) {
        if ((this->dp->gcs->err = gcry_cipher_encrypt(this->dp->gcs->h, outbuf, outlen, curbuf, outlen)) != 0) {
            fprintf(stderr, "encrypt failure: %s\n", gcry_strerror(this->dp->gcs->err));
        }
    }
    gcry_free(curbuf);
    return this->dp->gcs->err;
}

int
SymmetricKey::
 decrypt(char * outbuf,size_t outlen, const char *inbuf, size_t inlen) {
    if (!this->dp->initialized) {
        return 1;
    }
    if (!inbuf || inlen < 1) {
        fprintf(stderr, "gc_sym_decrypt invalid param: inbuf is null or empty\n");
        return 1;
    }
    if ((this->dp->gcs->err = gcry_cipher_decrypt(this->dp->gcs->h, outbuf, outlen, inbuf, inlen)) != 0) {
        fprintf(stderr,"decrypt failure: %s", gcry_strerror(this->dp->gcs->err));
    }
    return this->dp->gcs->err;
}

int
SymmetricKey::
 initRes(int algo, int mode) {

    int c_flags = 0;
    if (algo != GCRY_CIPHER_AES
        && algo != GCRY_CIPHER_AES192
        && algo != GCRY_CIPHER_AES256
        && algo != GCRY_CIPHER_DES
        && algo != GCRY_CIPHER_3DES
        && algo != GCRY_CIPHER_CAST5
        && algo != GCRY_CIPHER_TWOFISH
        && algo != GCRY_CIPHER_TWOFISH128
        && algo != GCRY_CIPHER_CAMELLIA128
        && algo != GCRY_CIPHER_CAMELLIA192
        && algo != GCRY_CIPHER_CAMELLIA256
    ) {
        fprintf(stderr, "invalid algo\n");
        return 1;
    }
    if (mode != GCRY_CIPHER_MODE_ECB
        && mode != GCRY_CIPHER_MODE_CFB
        && mode != GCRY_CIPHER_MODE_CBC
        && mode != GCRY_CIPHER_MODE_OFB
        && mode != GCRY_CIPHER_MODE_CTR
    ) {
        fprintf(stderr, "invalid block mode\n");
        return 1;
    }

    if ( !gcry_check_version (GCRYPT_VERSION) ) {
        fprintf(stderr, "version mismatch\n");
        return 1;
    }
    this->dp->gcs = (GCSYM *)malloc(sizeof(struct gc_sym_s));
    if (!this->dp->gcs) {
        fprintf(stderr, "cannot memory allocate for gc_sym_s\n");
        return 1;
    }
    this->dp->gcs->algo = algo;
    this->dp->gcs->mode = mode;
    this->dp->gcs->blklen = (size_t)gcry_cipher_get_algo_blklen(algo);
    this->dp->gcs->keylen = (size_t)gcry_cipher_get_algo_keylen(algo);

    this->dp->gcs->err = gcry_cipher_open( &(this->dp->gcs->h),
                            this->dp->gcs->algo, this->dp->gcs->mode, c_flags);
    if (this->dp->gcs->err != 0) {
        fprintf(stderr, "gcry_cipher_open failure\n");
        return this->dp->gcs->err;
    }
    return 0;
}

int
SymmetricKey::
 freeRes() {
    if (this->dp->initialized) {
        gcry_cipher_close(this->dp->gcs->h);
        free(this->dp->gcs);
    }
    return 0;
}

}; /* namespace cipher */

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: et sw=4 ts=4 fdm=marker
 * vim<600: et sw=4 ts=4
 */

