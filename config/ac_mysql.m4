dnl ---------------------------------------------------------------------------
dnl Macro: MYSQL_CONFIG
dnl ---------------------------------------------------------------------------

AC_DEFUN([MYSQL_CONFIG_TEST], [
  AC_MSG_CHECKING(for mysql_config tool)
  AC_ARG_WITH(mysql-config,
  [[  --with-mysql-config[=mysql config path]
                        mysql config path require to build engine.]],
  [
    if test -x "$withval"; then
        MYSQL_INCLUDES=`$withval --include`
        MYSQL_PLUGINDIR=`$withval --plugindir`
        MYSQL_CFLAGS=`$withval --cflags`
        MYSQL_LIB=`$withval --libs`
        AC_SUBST(MYSQL_INCLUDES)
        AC_SUBST(MYSQL_PLUGINDIR)
        AC_SUBST(MYSQL_CFLAGS)
        AC_SUBST(MYSQL_LIB)
    fi
  ],
  [
    AC_MSG_ERROR([mysql_config not found. Please specify --with-mysql-config.])
  ])
])


dnl ---------------------------------------------------------------------------
dnl Macro: MYSQL_CONFIG
dnl ---------------------------------------------------------------------------



