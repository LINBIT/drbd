#!/bin/bash
# drbd_config.h auto edit magic for 2.4 kernels ...

# expects KDIR in the environment to be set correctly!

set -e
sorry() {
	cat <<___
	Sorry, automagic adjustment of drdb_config.h failed.
	For well known 2.6. kernels, no adjustment to the shipped drbd_config is necessary.
	You need to verify it yourself.
___
}
trap "sorry" 0
grep_q() { grep "$@" /dev/null &>/dev/null ; }

# PARANOIA:
test -e ./linux/drbd_config.h || {
       echo >&2 "oops, invoked in unexpected directory..."
       exit 1
}

test -n "$KDIR"
KDIR=${KDIR%/}
if test -z "$O"; then
	O=$KDIR;
else
	O=${O%/}
fi

# some paranoia: check that all files are where we expect them
ls > /dev/null \
$KDIR/{Makefile,include/linux/{gfp,types}.h}
ls > /dev/null \
$O/{.config,Makefile,include/linux/version.h}
# test -e $KDIR/include/asm/bitops.h ||
# test -e $O/include2/asm/bitops.h   ||
# exit 1

if grep_q "^PATCHLEVEL *= *6" $KDIR/Makefile ; then
  # do we have gfp_t?
  if grep_q "typedef.*gfp_t" $KDIR/include/linux/gfp.h $KDIR/include/linux/types.h; then
    have_gfp_t=1
  else
    have_gfp_t=0
  fi
else
    # not a 2.6. kernel. just leave it alone...
    exit 0
fi

test -e ./linux/drbd_config.h.orig || cp ./linux/drbd_config.h{,.orig}

perl -pe "
 s{.*(#define KERNEL_HAS_GFP_T.*)}
  { ( $have_gfp_t ? '' : '//' ) . \$1}e;" \
	  < ./linux/drbd_config.h \
	  > ./linux/drbd_config.h.new


if ! DIFF=$(diff -s -U0 ./linux/drbd_config.h{,.new}) ; then
  mv ./linux/drbd_config.h{.new,}
  sed -e 's/^/  /' <<___

Adjusted drbd_config.h:
$DIFF

___
else
	rm ./linux/drbd_config.h.new
	echo -e "\n  Using unmodified drbd_config.h\n"
fi
trap - 0
exit 0
