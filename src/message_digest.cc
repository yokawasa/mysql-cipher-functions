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
#include "message_digest.h"

namespace cipher
{

static char hextab[] = "0123456789abcdef";
void
 _convToHex(const unsigned char *in, const size_t inlen, char* out, size_t *outlen) {
    size_t i, j;
    for (i = j = 0; i < inlen; i++) {
        out[j++] = hextab[in[i] >> 4];
        out[j++] = hextab[in[i] & 15];
    }
    out[j] = '\0';
    if (outlen) {
        *outlen = strlen(out);
    }
}

int
 getMessageDigestChecksum(const char* in, size_t inlen, int algo,
                                char *out, size_t *outlen) {
    size_t tmplen =0;
    unsigned char *tmpbuf;
    gcry_md_hd_t hd;
    gcry_error_t err = 0;

    err = gcry_md_open (&hd, algo, 0);
    if (err) {
        fprintf (stderr, "grcy_md_open failed : algo(%d) %s\n", algo, gpg_strerror (err));
        return 1;
    }
    tmplen = gcry_md_get_algo_dlen (algo);
    gcry_md_write (hd, in, inlen);
    tmpbuf = gcry_md_read (hd, algo);
    _convToHex(tmpbuf, tmplen, out, outlen);
    gcry_md_close (hd);
    return 0;
}

size_t
 getMessageDigestChecksumBuflen(int algo) {
    size_t tmpl = 0;
    tmpl = (size_t)gcry_md_get_algo_dlen (algo);
    return tmpl * 2 + 1;
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

