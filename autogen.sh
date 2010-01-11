#!/bin/sh

# for those that expect an autogen.sh,
# here it is.

autoheader
autoconf

echo "
suggested configure parameters:
./configure --prefix=/usr --localstatedir=/var --sysconfdir=/etc
"
