#!/bin/sh
#
# DRBD fence-peer handler for Pacemaker 1.1 clusters
# (via stonith-ng).
#
# Requires that the cluster is running with STONITH
# enabled, and has configured and functional STONITH
# agents.
#
# Also requires that the DRBD disk fencing policy
# is at least "resource-only", but "resource-and-stonith"
# is more likely to be useful as most people will
# use this in dual-Primary configurations.
#
# Returns 7 on on success (DRBD fence-peer exit code
# for "yes, I've managed to fence this node").
# Returns 1 on any error (undefined generic error code,
# causes DRBD devices with the "resource-and-stonith"
# fencing policy to remain suspended).

log() {
  local msg
  msg="$1"
  logger -i -t "`basename $0`" -s "$msg"
}

if [ -z "$DRBD_PEERS" ]; then
  log "DRBD_PEERS is empty or unset, cannot continue."
  exit 1
fi

for p in $DRBD_PEERS; do
  stonith_admin --fence $p
  rc=$?
  if [ $rc -eq 0 ]; then
    log "stonith_admin successfully fenced peer $p."
  else
    log "Failed to fence peer $p. stonith_admin returned $rc."
    exit 1
  fi
done

exit 7
