CREATE FUNCTION my_des_encrypt RETURNS STRING SONAME "cipher_functions.so";
CREATE FUNCTION my_des_decrypt RETURNS STRING SONAME "cipher_functions.so";
CREATE FUNCTION my_3des_encrypt RETURNS STRING SONAME "cipher_functions.so";
CREATE FUNCTION my_3des_decrypt RETURNS STRING SONAME "cipher_functions.so";
CREATE FUNCTION my_aes_encrypt RETURNS STRING SONAME "cipher_functions.so";
CREATE FUNCTION my_aes_decrypt RETURNS STRING SONAME "cipher_functions.so";
CREATE FUNCTION my_aes192_encrypt RETURNS STRING SONAME "cipher_functions.so";
CREATE FUNCTION my_aes192_decrypt RETURNS STRING SONAME "cipher_functions.so";
CREATE FUNCTION my_aes256_encrypt RETURNS STRING SONAME "cipher_functions.so";
CREATE FUNCTION my_aes256_decrypt RETURNS STRING SONAME "cipher_functions.so";

