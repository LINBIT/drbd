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
grep_q() { grep "$@" &>/dev/null ; }

# PARANOIA:
test -e ./linux/drbd_config.h || {
       echo >&2 "oops, invoced in unexpected directory..."
       exit 1
}

test -n "$KDIR"
KDIR=${KDIR%/}

ls >/dev/null \
$KDIR/{.config,Makefile,include/{linux/{version,sched,list,fs},asm/bitops}.h}


if grep_q "^PATCHLEVEL *= *4" $KDIR/Makefile ; then
  # do we have the threadding stuff in the kernel,
  # and need to use the sighand lock instead of the signal lock?
  if grep_q "^struct sighand_struct {" $KDIR/include/linux/sched.h ; then
    need_sighand_hack=1
  else
    need_sighand_hack=0
  fi

  # do we have hlist support already?
  if grep_q "^struct hlist_head {" $KDIR/include/linux/list.h; then
    hlist_backport=1
  else
    hlist_backport=0
  fi

  # is this a 2.4.18 kernel, which is supposed to have BH_launder,
  # but already has BH_Launder?
  if
    grep_q '^SUBLEVEL *= *18$' $KDIR/Makefile &&
    grep_q 'BH_Launder' $KDIR/include/linux/fs.h
  then
    need_RH_2_4_18_hack=1
  else
    need_RH_2_4_18_hack=0
  fi

  # do we have find_next_bit?
  if
    cat 2>/dev/null $KDIR/include/asm{,/arch}/bitops.h |
    grep_q 'find_next_bit'
  then
    # on ppc64, it's declared but not exported, so we use our own copy
    if grep_q '^CONFIG_PPC64=y' $KDIR/.config
    then
      have_find_next_bit=0
    else
      have_find_next_bit=1
    fi
  else
    have_find_next_bit=0
  fi

  # TODO autodetect whether we need this:
  # USE_GENERIC_FIND_NEXT_BIT
  # 

  # do we have mm_inline, and need to include it explicitly?
  if grep_q "#define *page_count" $KDIR/include/linux/mm_inline.h ; then
    have_mm_inline_h=1
  else
    have_mm_inline_h=0
  fi
else
    # 2.6. kernel. just leave it alone...
    need_sighand_hack=0
    hlist_backport=0
    need_RH_2_4_18_hack=0
    have_find_next_bit=0
    have_mm_inline_h=0
fi

test -e ./linux/drbd_config.h.orig || cp ./linux/drbd_config.h{,.orig}

perl -pe "
 s{.*(#define SIGHAND_HACK.*)}
  { ( $need_sighand_hack ? '' : '//' ) . \$1}e;
 s{.*(#define REDHAT_HLIST_BACKPORT.*)}
  { ( $hlist_backport ? '' : '//' ) . \$1}e;
 s{.*(#define REDHAT_2_4_18.*)}
  { ( $need_RH_2_4_18_hack ? '' : '//' ) . \$1}e;
 s{.*(#define HAVE_FIND_NEXT_BIT.*)}
  { ( $have_find_next_bit ? '' : '//' ) . \$1}e;
 s{.*(#define HAVE_MM_INLINE_H.*)}
  { ( $have_mm_inline_h ? '' : '//' ) . \$1}e;" \
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
