##
## Toplevel Makefile.am for rng-tools
##

SUBDIRS		= contrib

sbin_PROGRAMS	 = rngd
bin_PROGRAMS	 = rngtest
man_MANS	 = rngd.8 rngtest.1
noinst_LIBRARIES = librngd.a

common_sources	= exits.h fips.h stats.h
rngd_SOURCES	= $(common_sources) rngd.h rngd.c \
		  rngd_threads.h rngd_threads.c \
		  rngd_entsource.h rngd_entsource.c \
		  rngd_linux.h rngd_linux.c
rngd_LDADD	= librngd.a @LIB_PTHREAD@

rngtest_SOURCES	= $(common_sources) rngtest.c
rngtest_LDADD	= librngd.a

librngd_a_SOURCES = fips.h fips.c stats.h stats.c


EXTRA_DIST	= autogen.sh

