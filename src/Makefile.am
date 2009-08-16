# Used to build Makefile.in
# Yoichi Kawasaki <yokawasa@gmail.com>
pkgplugindir = $(MYSQL_PLUGINDIR)
libdir = $(MYSQL_PLUGINDIR)
INCLUDES = -I$(top_builddir)/include $(MYSQL_INCLUDES) $(LIBGCRYPT_CFLAGS)
noinst_HEADERS =
lib_LTLIBRARIES = cipher_functions.la
cipher_functions_la_SOURCES = cipher_functions.cc symmetric_key.cc
cipher_functions_la_LIBADD = $(LIBGCRYPT_LIBS)
cipher_functions_la_LDFLAGS = -module -rpath $(pkgplugindir)
cipher_functions_la_CFLAGS = $(AM_CFLAGS)
cipher_functions_la_CXXFLAGS = $(AM_CFLAGS)
