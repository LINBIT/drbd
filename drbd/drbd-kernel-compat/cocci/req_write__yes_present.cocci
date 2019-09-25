// PART 0: General fixups
@@
identifier op, op_flags;
struct bio *b;
iterator it;
@@
drbd_submit_peer_request(...,
-	unsigned op
+	unsigned rw
	,
-	unsigned int op_flags,
	...)
{
...
// with the old system, the bio implicitly has to be either "read" or "write", so we can delete this whole check.
- if (!(op == REQ_OP_WRITE || op == REQ_OP_READ)) {
-...
-}
...
-b->bi_opf = op | op_flags;
+b->bi_rw = rw;
...
it(...) {
...
-(op == REQ_OP_READ)
+!(rw & REQ_WRITE)
...
}
...
}

@@
@@
-wire_flags_to_bio_op(...) {...}

@@
typedef u32;
identifier connection, dpf;
@@
static unsigned long
-wire_flags_to_bio_flags
+wire_flags_to_bio
 (struct drbd_connection *connection, u32 dpf)
{
if (connection->agreed_pro_version >= 95)
                return  (dpf & DP_RW_SYNC ? REQ_SYNC : 0) |
                        (dpf & DP_FUA ? REQ_FUA : 0) |
-                       (dpf & DP_FLUSH ? REQ_PREFLUSH : 0);
+                       (dpf & DP_DISCARD ? REQ_DISCARD : 0) |
+#ifdef REQ_WRITE_SAME
+                       (dpf & DP_WSAME ? REQ_WRITE_SAME : 0) |
+#endif
+                       (dpf & DP_FLUSH ? REQ_FLUSH : 0);
...
}

//------------------------------------------------------------------------------
// PART 1: REQ_OP_READ
// What we have: a full value, bio->bi_opf set to REQ_OP_READ
// What we want: the lowest bit (REQ_WRITE) of bio->bi_rw unset

@ disable bitand_comm, not_int1, not_int2, commeq, ptr_to_array @
struct bio *b;
@@
static void drbd_req_complete(...)
{
<...
// a little special case...
-(!ok && bio_op(b) == REQ_OP_READ && !(b->bi_opf & REQ_RAHEAD))
+(!ok && b->bi_rw & READ)
...>
}

@@
@@
bm_page_io_async(...)
{
...
unsigned int
-op
+rw
= ... ?
-REQ_OP_READ
+READ
:
-REQ_OP_WRITE
+WRITE
;
<...
-(op == REQ_OP_WRITE)
+(rw & WRITE)
...>
}

@@
struct bio *b;
@@
(
- bio_op(b) == REQ_OP_READ
+ !(b->bi_rw & REQ_WRITE)
|
- bio_op(b) != REQ_OP_READ
+ (b->bi_rw & REQ_WRITE)
)

@@
struct bio *b;
identifier o;
@@
unsigned int o = bio_op(b);
<...
(
- o == REQ_OP_READ
+ !(b->bi_rw & REQ_WRITE)
|
- o != REQ_OP_READ
+ (b->bi_rw & REQ_WRITE)
)
...>

@@
expression device, peer_req, flags, fault_type;
@@
(
drbd_submit_peer_request(device, peer_req
-, REQ_OP_READ, flags
+, READ | flags
, fault_type)
|
drbd_submit_peer_request(device, peer_req
-, REQ_OP_WRITE, flags
+, WRITE | flags
, fault_type)
|
drbd_submit_peer_request(device, peer_req
-, REQ_OP_WRITE_ZEROES, flags
+, (-3) /* WRITE_ZEROES not supported on this kernel */
, fault_type)
|
drbd_submit_peer_request(device, peer_req
-, op, op_flags
+, rw
, fault_type)
)

//------------------------------------------------------------------------------
// PART 2: drbd_md_sync_page_io
@@
@@
drbd_md_sync_page_io(...
-, int op
+, int rw
 )
{
<...
-(op == REQ_OP_WRITE)
+(rw & WRITE)
? ... ;
...>
}

@@
@@
_drbd_md_sync_page_io(...
-, int op
+, int rw
 )
{
...
-int op_flags = ...;
<...
(
-op_flags |=
+rw |=
...;
|
-(op == REQ_OP_WRITE)
+(rw & WRITE)
|
-(op != REQ_OP_WRITE)
+!(rw & WRITE)
)
...>
}

@@
@@
_drbd_md_sync_page_io(...
-, op
+, rw
 )

@@
@@
(
drbd_md_sync_page_io(...
-, REQ_OP_WRITE
+, WRITE
 )
|
drbd_md_sync_page_io(...
-, REQ_OP_READ
+, READ
 )
)

//------------------------------------------------------------------------------
// PART 3: REQ_OP_WRITE_ZEROES
@@
struct bio *b;
@@
(
- (bio_op(b) == REQ_OP_WRITE_ZEROES)
+ (false) /* WRITE_ZEROES not supported on this kernel */
|
- (bio_op(b) != REQ_OP_WRITE_ZEROES)
+ (true) /* WRITE_ZEROES not supported on this kernel */
)

@@
identifier pd, o;
@@
-D_ASSERT(pd, o == REQ_OP_WRITE_ZEROES);

@ exists @
type T;
identifier o, fn;
expression flags;
struct bio *b;
@@
fn(...) {
<...
(
T o = bio_op(b);
|
o = bio_op(b);
|
o = wire_flags_to_bio_op(flags);
)
...
(
- o == REQ_OP_WRITE_ZEROES
+ (false) /* WRITE_ZEROES not supported on this kernel */
|
- o != REQ_OP_WRITE_ZEROES
+ (true) /* WRITE_ZEROES not supported on this kernel */
)
...>
}

@@
@@
-REQ_OP_WRITE_ZEROES
+(-3) /* WRITE_ZEROES not supported on this kernel */

//------------------------------------------------------------------------------
// PART 4: bi_opf -> bi_rw
@@
struct bio *b;
constant op, op_flags;
@@
-b->bi_opf = REQ_OP_FLUSH | REQ_PREFLUSH;
+submit_bio(WRITE_FLUSH, bio);
<...
-submit_bio(b);
...>

@@
struct bio *b;
symbol op, op_flags, rw;
@@
(
-b->bi_opf = op | op_flags;
+b->bi_rw = rw;
|
-b->bi_opf = op;
+b->bi_rw = rw;
)
<...
-submit_bio(b);
+submit_bio(rw, b);
...>

@@
struct bio *b;
constant flag;
@@
-b->bi_opf & flag
+b->bi_rw & flag

@@
struct bio *b;
@@
-b->bi_opf &=
+b->bi_rw &=
...;

//------------------------------------------------------------------------------
// PART n: Generic REQ_OP_* -> REQ_*

@ find_req_ops @
identifier req_op =~ "REQ_OP_.*";
position p;
@@
req_op@p

@ script:python transform_req_ops @
req_op << find_req_ops.req_op;
p << find_req_ops.p;
req;
@@
import sys
replacements = {
	"REQ_OP_WRITE": "REQ_WRITE",
	"REQ_OP_FLUSH": "REQ_FLUSH",
	"REQ_OP_DISCARD": "REQ_DISCARD",
	"REQ_OP_WRITE_SAME": "REQ_WRITE_SAME"
}

if req_op in replacements:
	coccinelle.req = replacements[req_op]
	#coccilib.report.print_report(p[0], 'replacing %s' % req_op)
else:
	msg = 'ERROR: unknown operation %s, fix compat layer!' % req_op
	coccilib.report.print_report(p[0], msg)
	sys.exit(1)

@@
identifier find_req_ops.req_op;
identifier transform_req_ops.req;
struct bio *b;
@@
(
- (bio_op(b) == req_op)
+ (b->bi_rw & req)
|
- bio_op(b) != req_op
+ !(b->bi_rw & req)
)

@ exists @
identifier find_req_ops.req_op;
identifier transform_req_ops.req;
identifier o, fn;
expression flags;
type T;
struct bio *b;
@@
fn(...) {
<...
(
T o = bio_op(b);
|
o = bio_op(b);
)
...
(
- o == req_op
+ (b->bi_rw & req)
|
- o != req_op
+ !(b->bi_rw & req)
)
...>
}

@ exists @
identifier find_req_ops.req_op;
identifier transform_req_ops.req;
identifier o, fn;
expression flags;
struct bio *b;
type T;
@@
fn(...) {
<...
(
T o = wire_flags_to_bio_op(flags);
|
o = wire_flags_to_bio_op(flags);
)
...
(
- o == req_op
+ (rw & req)
|
- o != req_op
+ !(rw & req)
)
...>
}

//------------------------------------------------------------------------------
// PART n+1: Clean up any bio_op calls
@@
struct bio *b;
type T;
identifier o;
@@
-T o = bio_op(b);

@@
expression connection, flags;
symbol op, op_flags;
identifier fn;
@@
fn(...)
{
...
int
-op
+rw = WRITE
;
...
-op = wire_flags_to_bio_op(flags);
-op_flags = wire_flags_to_bio_flags(connection, flags);
+rw |= wire_flags_to_bio(connection, flags);
<...
(
-op == REQ_OP_DISCARD
+rw & REQ_DISCARD
|
// we do not support WRITE_ZEROES
-op == REQ_OP_WRITE_ZEROES
+false
|
-op_flags |=
+rw |=
...
)
...>
}
