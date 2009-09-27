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
#ifndef _MYSQL_CIPHER_FUNCTIONS_MESSAGE_DIGEST_H_
#define _MYSQL_CIPHER_FUNCTIONS_MESSAGE_DIGEST_H_

#include <string.h>

namespace cipher
{
    int getMessageDigestChecksum(const char* in, size_t inlen, int algo,
                                char *out, size_t *outlen);

    size_t getMessageDigestChecksumBuflen(int algo);

}; /* namespace cipher */

#endif /* _MYSQL_CIPHER_FUNCTIONS_MESSAGE_DIGEST_H_ */

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: et sw=4 ts=4 fdm=marker
 * vim<600: et sw=4 ts=4
 */

