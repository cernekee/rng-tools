#!/bin/sh
#
# Debian autogen.sh glue for rng-tools
# $Id: autogen.sh,v 1.5 2003/12/25 20:58:23 hmh Exp $
#
# Requires: automake, autoconf (newest versions), dpkg-dev
set -e

# Refresh GNU autotools toolchain.
rm -rf autom4te.cache
aclocal-1.7 
autoheader2.50
automake-1.7 --gnu --add-missing

# The automake package already links config.sub/guess to /usr/share/misc/
for i in missing install-sh mkinstalldirs depcomp; do
	test -r /usr/share/automake-1.7/${i} && {
		rm -f "${i}"
		cp -f "/usr/share/automake-1.7/${i}" .
	}
	chmod 755 "${i}"
done

autoconf2.50

exit 0
