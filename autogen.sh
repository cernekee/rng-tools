#!/bin/sh
#
# autogen.sh glue for rng-tools
#
# Requires: automake 1.9, autoconf 2.57+
# conflicts: automake, autoconf (Debian 2.13/1.4 versions)
set -e

# Refresh GNU autotools toolchain.
rm -rf autom4te.cache
rm -f missing install-sh mkinstalldirs depcomp
rm -f config.sub config.guess
# we use the std. GNU ones
rm -f INSTALL COPYING

autoreconf -i

exit 0
