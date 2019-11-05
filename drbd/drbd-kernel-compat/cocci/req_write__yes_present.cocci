// PART 0: General fixups
@@
@@
struct drbd_peer_request {
...
unsigned int
-opf
+rw
;
...
}

@@
@@
-#define peer_req_op(...) (...)

@@
identifier peer_req;
struct bio *b;
@@
drbd_submit_peer_request(...)
{
...
-b->bi_opf = peer_req->opf;
+b->bi_rw = peer_req->rw;
...
}

@@
identifier peer_req;
@@
drbd_err(...,
-peer_req->opf);
+peer_req->rw);

@@
@@
-wire_flags_to_bio_op(...) {...}

@@
identifier dpf;
@@
(
-               wire_flags_to_bio_op(dpf)
+               REQ_WRITE |
+               (dpf & DP_DISCARD ? REQ_DISCARD : 0)
+#ifdef REQ_WRITE_SAME
+               | (dpf & DP_WSAME ? REQ_WRITE_SAME : 0)
+#endif
)

@@
@@
(
-REQ_PREFLUSH
+REQ_FLUSH
)

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
+(!ok && !(b->bi_rw & REQ_WRITE))
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
+0
:
-REQ_OP_WRITE
+REQ_WRITE
;
<...
-(op == REQ_OP_WRITE)
+(rw & REQ_WRITE)
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
struct drbd_peer_request *peer_req;
@@
(
- peer_req_op(peer_req) == REQ_OP_READ
+ !(peer_req->rw & REQ_WRITE)
|
- peer_req_op(peer_req) != REQ_OP_READ
+ (peer_req->rw & REQ_WRITE)
)

@@
struct drbd_peer_request *peer_req;
@@
- peer_req->opf =
+ peer_req->rw =
(
- REQ_OP_READ
+ 0
|
// REQ_OP_WRITE_ZEROES replacement.
// Start line with space to avoid spatch parsing it as a disjunction.
 (-3)
|
wire_flags_to_bio(...)
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
+(rw & REQ_WRITE)
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
+(rw & REQ_WRITE)
|
-(op != REQ_OP_WRITE)
+!(rw & REQ_WRITE)
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
+, REQ_WRITE
 )
|
drbd_md_sync_page_io(...
-, REQ_OP_READ
+, 0
 )
)

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
struct drbd_peer_request *peer_req;
@@
(
- peer_req_op(peer_req) == req_op
+ (peer_req->rw & req)
|
- peer_req_op(peer_req) != req_op
+ !(peer_req->rw & req)
)

@@
identifier find_req_ops.req_op;
identifier transform_req_ops.req;
struct drbd_peer_request *peer_req;
symbol opf;
@@
- peer_req->opf = req_op;
+ peer_req->rw = req;

//------------------------------------------------------------------------------
// PART n+1: Clean up any bio_op calls
@@
struct bio *b;
type T;
identifier o;
@@
-T o = bio_op(b);

@@
identifier peer_req;
@@
-peer_req->opf |=
+peer_req->rw |=
...;
