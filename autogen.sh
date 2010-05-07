#!/bin/sh
#
# autogen.sh glue for rng-tools
#
# Requires: automake, autoconf (see configure.ac for version info)
set -e

# Refresh GNU autotools toolchain.
rm -rf autom4te.cache
rm -f missing install-sh mkinstalldirs depcomp
rm -f config.sub config.guess
# we use the std. GNU one
rm -f INSTALL

autoreconf -i

exit 0
