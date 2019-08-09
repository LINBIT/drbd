@@
symbol op_flags;
@@
// since there's only one occurrence of this in the drbd code, let's just
// hardcode this.
_drbd_md_sync_page_io(...)
{
...
if(...) {
	op_flags |= ...;
}
op_flags |=
+ REQ_NOIDLE |
...;
...
}
