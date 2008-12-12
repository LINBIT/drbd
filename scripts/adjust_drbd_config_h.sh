#!/bin/bash
# drbd_config.h auto edit magic for 2.4 kernels ...

# expects KDIR in the environment to be set correctly!

set -e
sorry() {
	cat <<___
	Sorry, automagic adjustment of drbd_config.h failed.
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

# ok, now we have a KDIR; cd into it, in case we detect relative pathes
pushd $KDIR

KDIR=${KDIR%/}
if test -z "$O"; then
	## just in case...
	## detect if $KDIR points to something which is actually $O ...
	X=$( make help | sed -ne '/ -C .* O=.* help$/p' | tr -s ' ' )
	if [[ -n $X ]]; then
		KDIR=${X##* -C }; KDIR=${KDIR%% *}; KDIR=$(cd $KDIR && pwd)
		O=${X##* O=}; O=${O%% *}; O=$(cd $KDIR && cd $O && pwd)
	else
		O=$KDIR;
	fi
else
	O=${O%/}
fi

# some paranoia: check that all files are where we expect them
ls > /dev/null \
$KDIR/{Makefile,include/linux/{gfp,types,slab,net}.h}
ls > /dev/null \
$O/{.config,Makefile,include/linux/version.h}
test -e $O/include/asm/atomic.h  ||
test -e $O/include/asm/arch/atomic.h  ||
test -e $O/include2/asm/atomic.h ||
exit 1

if grep_q "^PATCHLEVEL *= *6" $KDIR/Makefile ; then
  # do we have gfp_t?
  if grep_q "typedef.*gfp_t" $KDIR/include/linux/gfp.h $KDIR/include/linux/types.h; then
    have_gfp_t=1
  else
    have_gfp_t=0
  fi
  # stupid vendor kernels grrr...
  have_atomic_add=0
  # btw, don't ask why I don't use grep -qs $a $b $c 
  # it simply does not work always...
  for f in $O/include/asm/atomic.h \
    $O/include/asm/arch/atomic.h \
    $O/include2/asm/atomic.h \
    $O/include/asm/atomic_32.h \
    $O/include2/asm/atomic_32.h \
    $O/include/asm/arch/atomic_32.h
  do
    if grep_q "atomic_add_return" $f; then
      have_atomic_add=1
      break
    fi
  done
  if grep_q "typedef.*kmem_cache_s" $KDIR/include/linux/slab.h ; then
    have_kmem_cache_s=1
  else
    have_kmem_cache_s=0
  fi
  if grep_q "sock_create_kern" $KDIR/include/linux/net.h ; then
    have_sock_create_kern=1
  else
    have_sock_create_kern=0
  fi
  if grep_q "dst_groups" $KDIR/include/linux/netlink.h ; then
    have_nl_dst_groups=1
  else
    have_nl_dst_groups=0
  fi
  if grep_q "kzalloc" $KDIR/include/linux/slab.h ; then
    need_backport_of_kzalloc=0
  else
    need_backport_of_kzalloc=1
  fi
  if test -e $KDIR/include/linux/scatterlist.h ; then
    have_linux_scatterlist_h=1
    if grep_q "sg_set_buf" $KDIR/include/linux/scatterlist.h ; then
      need_sg_set_buf=0
    else
      need_sg_set_buf=1
    fi
  else
    have_linux_scatterlist_h=0
    need_sg_set_buf=1
  fi
  if grep_q "msleep" $KDIR/include/linux/delay.h ; then
    have_msleep=1
  else
    have_msleep=0
  fi
  if grep_q "kvec" $KDIR/include/linux/uio.h ; then
    have_kvec=1
  else
    have_kvec=0
  fi
else
    # not a 2.6. kernel. just leave it alone...
    exit 0
fi

# and back do drbd source
popd

test -e ./linux/drbd_config.h.orig || cp ./linux/drbd_config.h{,.orig}

perl -pe "
 s{.*(#define KERNEL_HAS_GFP_T.*)}
  { ( $have_gfp_t ? '' : '//' ) . \$1}e;
 s{.*(#define NEED_BACKPORT_OF_ATOMIC_ADD.*)}
  { ( $have_atomic_add ? '//' : '' ) . \$1}e;
 s{.*(#define USE_KMEM_CACHE_S.*)}
  { ( $have_kmem_cache_s ? '' : '//' ) . \$1}e;
 s{.*(#define DEFINE_SOCK_CREATE_KERN.*)}
  { ( $have_sock_create_kern ? '//' : '' ) . \$1}e;
 s{.*(#define DRBD_NL_DST_GROUPS.*)}
  { ( $have_nl_dst_groups ? '' : '//' ) . \$1}e;
 s{.*(#define NEED_BACKPORT_OF_KZALLOC.*)}
  { ( $need_backport_of_kzalloc ? '' : '//' ) . \$1}e;
 s{.*(#define NEED_SG_SET_BUF.*)}
  { ( $need_sg_set_buf ? '' : '//' ) . \$1}e;
 s{.*(#define HAVE_LINUX_SCATTERLIST_H.*)}
  { ( $have_linux_scatterlist_h ? '' : '//' ) . \$1}e;
 s{.*(#define KERNEL_HAS_MSLEEP.*)}
  { ( $have_msleep ? '' : '//' ) . \$1}e;
 s{.*(#define KERNEL_HAS_KVEC.*)}
  { ( $have_kvec ? '' : '//' ) . \$1}e;
 " \
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
