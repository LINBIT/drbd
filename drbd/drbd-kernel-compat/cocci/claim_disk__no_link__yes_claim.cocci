@@
expression bde, vdisk;
@@
link_backing_dev(...
+, void *claim_ptr
 )
{
...
- bd_link_disk_holder(bde, vdisk)
+ bd_claim_by_disk(bde, claim_ptr, vdisk)
...
}

@@
identifier bde;
expression list args;
expression claim_ptr_value;
@@
open_backing_devices(...)
{
+ void *claim_ptr;
<+...
(
- bde = open_backing_dev(args, claim_ptr_value);
+ claim_ptr = claim_ptr_value;
+ bde = open_backing_dev(args, claim_ptr);
|
link_backing_dev(...
+, claim_ptr
 )
)
...+>
}

@@
expression bde, vdisk;
@@
- bd_unlink_disk_holder(bde, vdisk)
+ bd_release_from_disk(bde, vdisk)
