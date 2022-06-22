=========================================
Application and Resync IO Synchronization
=========================================

This summary describes one aspect of the Distributed Replicated Block Device
(DRBD) protocol. For a full definition of the protocol see the DRBD code.

IO operations to the DRBD backing device can originate from 2 sources. Normal
operations from a filesystem or other user of DRBD are called application IO.
Resync operations in DRBD also perform reads and writes. These operations must
be synchronized to ensure that the data on the backing device is correct.

For instance, the following must be prevented:

* Resync read obtains block version v1 on some node
* Application writes block version v2 on all nodes
* Resync write overwrites block version v2 with version v1

In addition, care must be taken to ensure that bitmap bits are only cleared
when this block is genuinely in sync between these nodes.

Synchronization with resync extents
===================================

Older versions of DRBD without the feature flag ``DRBD_FF_RESYNC_DAGTAG``
perform synchronization using "resync extents". These are also known as "bitmap
extents". They are stored in an LRU cache. These extents are exclusive with the
activity log extents.

Synchronization with data generation tags
=========================================

When the feature flag ``DRBD_FF_RESYNC_DAGTAG`` is present, DRBD synchronizes
resync and application IO using the concept of the "data generation tag"
(dagtag). This is coupled with fine-grained locking of the request intervals,
implemented internally using an interval tree.

For a given node, the dagtag is the number of sectors written by the
application on that node. The dagtag is used to determine which node has newer
data in certain scenarios. DRBD keeps track of the dagtags of its peers.

Whenever a resync request is made, the ``L_SYNC_TARGET`` node making the
request sends the dagtag from the current Primary node, if any. The
``L_SYNC_SOURCE`` node must wait until it has received the data corresponding
to this dagtag before responding to the resync request. This is important for
preventing the resync from writing older data over newer data.

In addition, the request intervals are locked according to the following
scheme:

* Primary: The application IO interval is locked while the data is being
  written to the backing disk. In addition, conflicting application IO is
  prevented until the epoch containing the request is complete. However, this
  is effectively a separate lock. Resync IO is not blocked while this lock is
  held.
* Secondary: The application IO interval is locked while the data is being
  written to the backing disk.
* Sync target: The ``P_RS_DATA_REQUEST`` interval is locked. The lock is taken
  in two phases. Before sending the request, the interval is locked for
  conflicts with other peers. Then the dagtag is recorded and the request is
  sent. When the reply is received, the interval is additionally locked for
  conflicts with ongoing IO, in particular writes from the same peer. The lock
  is released when the reply has been received and the data written to the
  backing disk.
* Sync source: The ``P_RS_DATA_REQUEST`` interval is locked. The lock is taken
  when the dagtag for the request is reached. It is released when the
  ``P_RS_WRITE_ACK`` is received. This lock is a read lock; it is exclusive
  with write locks, but not with other read locks.
* Verify source: The online verify interval is marked but does not block any
  other requests. The mark is set then the dagtag is recorded and the request
  is sent. The mark is removed when the ``P_OV_REPLY`` has been received, the
  dagtag from the reply has been reached and the data read. If any conflicting
  writes occur while the mark is set, the sectors are skipped.
* Verify target: The online verify interval is marked but does not block any
  other requests. The mark is set when the dagtag for the request has been
  reached. It is removed after reading the data. The latest dagtag received by
  this node is sent with the ``P_OV_REPLY``. If any conflicting writes occur
  while the mark is set, the sectors are skipped.
* Sending ``P_PEERS_IN_SYNC``: Intervals are briefly locked while sending
  ``P_PEERS_IN_SYNC`` to ensure that the bits remain in sync until the packet
  has been sent.

If a conflict occurs when an interval should be locked, the request is delayed
until the conflict resolves. Internally this is implemented by storing the
interval in the tree in an unlocked form. When an interval is removed from the
tree, the tree is searched for any intervals which can now be released.

Application IO defers to resync IO. That is, application IO is blocked by
resync IO even when that resync IO has not yet obtained the lock for its
interval. This is important for ensuring progress. In the normal case, resyncs
only make one pass through the data. Hence they will eventually terminate.
Application IO, on the other hand, can keep a given region busy for an
arbitrary length of time. So resync IO must not wait indefinitely for
application IO.

Correctness of data
-------------------

We only consider the synchronization between application and resync IO here.

The locking scheme prevents any writes from other peers to the resync request
interval from when the request is initiated until the received data is written.
After the lock is taken on the target, the dagtag is recorded and the request
is sent to the source. The source then waits until it has reached this dagtag
before reading. This ensures that the resync data is at least as new as the
data on the target when the request was made.

Conflicting application writes that reach the target while the resync request
is in progress are held until the resync data has been written. Hence they
overwrite the resync data. In the case where the source had already received
this application write when it performed the resync read, the application write
will overwrite the resync write on the target with identical data. This is
harmless.

Resync requests sent from the target are not exclusive with application writes
from the same peer. However, since the resync and application data originate
from the same node, they are transmitted in the correct order in the data
stream. Application IO defers to received resync IO, ensuring that a resync
write received before an application write is also submitted first.

Correctness of bitmap bits
--------------------------

DRBD guarantees that bitmap bits are set, or the corresponding activity log
extent is active, on at least one peer whenever 2 nodes are out of sync with
each other. A resync is called "stable" when the target is a neighbor of the
Primary node, if there is one. After a stable resync, all bitmap bits should be
clear. In other situations, DRBD makes a best effort attempt to clear bits when
appropriate.

Hence we need to ensure that:

1. Bits are set when out of sync
2. Bits are only cleared when in sync
3. Bits are cleared in a stable resync

We are only considering the synchronization of application and resync IO here,
so we only need to consider interactions between the 2 types. Requirement (1)
holds due to the general design for how writes work in DRBD. Requirement (3)
holds because there is no operation that sets bits in a stable resync. The
potential issues with these interactions arise with requirement (2). We need to
ensure that bits are never cleared that have become out of sync during the
operation.

On a Primary node, writes cause bits to be set and cleared when the
corresponding ``P_BARRIER_ACK`` packets are received. On a Secondary node,
writes cause bits to be set and cleared when the corresponding ``P_PEER_ACK``
is received. On a sync target, bits are cleared when the resync data has been
written. On a sync source, bits are cleared when ``P_RS_WRITE_ACK`` is
received.

The bits cleared by writes must always be in sync because the corresponding
nodes have received the write. As demonstrated in the section "correctness of
data", they cannot lose this data due to a resync.

For a stable resync, bits will not become out of sync for the peer device on
either side during the resync operation because both peers receive the
application writes.

On a sync target for an unstable resync, no application writes are received, so
there will be no bits set that could be incorrectly cleared.

On a sync source for an unstable resync, the interval is locked until
``P_RS_WRITE_ACK`` is received. Hence, when the bit is cleared, the target has
the same data for the interval as the source. That is, they are still in sync.

For ``P_PEERS_IN_SYNC`` we consider only the 3 node case. There is only one
configuration with an unstable resync with 3 nodes. That is a chain
A - B - C with A being Primary and a sync from B to C. The only
``P_PEERS_IN_SYNC`` packets that have an effect in this configuration are those
from B to A indicating that C is in sync for some interval. B only sends this
packet when no bitmap bits are set towards C for the interval. In addition,
B must ensure that no application write causes bits to be incorrectly cleared
on A towards C. This could occur when B has sent ``P_BARRIER_ACK`` for a write
which is not yet represented in its bitmap towards C. So B must not send
``P_PEERS_IN_SYNC`` for an interval where this may be the case. To do this, it
checks that there is no activity in the activity log that overlaps with this
interval. To ensure that no writes occur between this check and sending
``P_PEERS_IN_SYNC``, it locks the interval temporarily.

Deadlock safety
---------------

We can ignore the locking of application IO until the containing epoch is
complete. No other lock acquisition depends on it. To put it another way, it
operates on a level above the rest of the locking.

The locking on Primary and Secondary while application IO is being written to
the backing disk does not depend on any other lock acquisition. So it is
guaranteed that a locked interval of this type will eventually be unlocked.

Online verify does not block any other operations, so cannot be involved in
causing a deadlock.

Sending ``P_PEERS_IN_SYNC`` also cannot be involved in causing a deadlock
because it does not depend on any other lock acquisition.

Resync requests depend on the corresponding peer. If the connection is lost,
the operation is aborted, so no deadlock will occur as a result of
non-responsive peers.

A node cannot be both sync source and sync target simultaneously. Hence there
are no locks in the scheme which can block sync source reads indefinitely. So
a resync request from a sync target will always eventually receive a reply,
which allows it to perform the write and unlock its interval. This in turn
guarantees that the sync source will receive an ack and unlock its interval.

Hence the locking scheme itself is free from distributed deadlocks.
