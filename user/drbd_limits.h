/*
  drbd_limits.h
  This file is part of drbd by Philipp Reisner / Lars Ellenberg.
*/

/*
 * Our current limitations.
 * Some of them are hard limits,
 * some of them are arbitrary range limits, that make it easier to provide
 * feedback about nonsense settings for certain configurable values.
 */

#ifndef DRBD_LIMITS_H
#define DRBD_LIMITS_H 1

#define DEBUG_RANGE_CHECK 0

#define RANGE(what,min,max) \
const unsigned long long DRBD_ ## what ## _MIN = (min); \
const unsigned long long DRBD_ ## what ## _MAX = (max)

RANGE(MINOR_COUNT,1,255);
RANGE(DIALOG_REFRESH,0,600);

/* valid port number */
RANGE(PORT,1,0xffff);


/* startup { */
  /* if you want more than 3.4 days, disable */
  RANGE(WFC_TIMEOUT,0,300000);
  RANGE(DEGR_WFC_TIMEOUT,0,300000);
/* }*/

/* net { */
  /* timeout, unit centi seconds
   * more than one minute timeout is not usefull */
  RANGE(TIMEOUT,1,600);

  /* active connection retries when WFConnection */
  RANGE(CONNECT_INT,1,120);

  /* keep-alive probes when idle */
  RANGE(PING_INT,1,120);

  /* max number of write requests between write barriers */
  RANGE(MAX_EPOCH_SIZE,1,20000);

  /* I don't think that a tcp send buffer of more than 10M is usefull */
  RANGE(SNDBUF_SIZE, 1, 10000000);

  /* arbitrary. */
  RANGE(MAX_BUFFERS, 32, 5000);

  /* 0 is disabled.
   * 200 should be more than enough even for very short timeouts */
  RANGE(KO_COUNT,0, 200);
/* } */

/* syncer { */
  /* FIXME allow rate to be zero? */
  RANGE(RATE,1,700000);

  /* arbitrary. you have more than device numbers now. */
  RANGE(GROUP,0,1000);

  /* less than 7 would hit performance unneccessarily.
   * 3833 is the largest prime that still does fit
   * into 64 sectors of activity log */
  RANGE(AL_EXTENTS, 7, 3833);
/* } */

/* drbdsetup XY resize -d Z
 * you are free to reduce the device size to nothing, if you want to.
 * but more than 3998G are currently not possible */
/* DRBD_MAX_SECTORS */
RANGE(DISK_SIZE_SECT, 0, (128LLU*1024*2 - 72)*512LLU*8*8 );

#undef RANGE
#endif
