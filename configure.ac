dnl For cipher_functions MySQL
AC_INIT(src/cipher_functions.cc)
AC_CONFIG_AUX_DIR(config)
AM_CONFIG_HEADER(src/config.h)
AM_INIT_AUTOMAKE("cipher_functions", 0.1)

# Checks for programs.
AC_PROG_CC
AC_PROG_CXX
AC_PROG_CPP
AC_PROG_GCC_TRADITIONAL
AC_PROG_LIBTOOL

# Checks for libraries.
AC_SUBST(CFLAGS)
AC_SUBST(CXXFLAGS)
sinclude(config/ac_mysql.m4)
MYSQL_CONFIG_TEST
sinclude(config/libgcrypt.m4)
gcrypt_found=0
AM_PATH_LIBGCRYPT(1.2.0, gcrypt_found=1)
if test $gcrypt_found = 0
then
  AC_MSG_ERROR([mysql_cipher_functions needs libgcrypt])
fi

# Checks for header files.
AC_CHECK_HEADERS(limits.h syslimits.h)

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_SIZE_T

AC_OUTPUT(Makefile src/Makefile)
