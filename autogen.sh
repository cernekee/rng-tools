#!/bin/sh
#
# autogen.sh glue for rng-tools
#
# Requires: automake 1.8, autoconf 2.57+
set -e

# Refresh GNU autotools toolchain.
rm -rf autom4te.cache
rm -f missing install-sh mkinstalldirs depcomp
aclocal-1.8
autoheader2.50
automake-1.8 --gnu --add-missing --copy
autoconf2.50

exit 0
