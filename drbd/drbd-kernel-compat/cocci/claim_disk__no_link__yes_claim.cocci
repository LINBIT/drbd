@@
expression bde, vdisk;
@@
(
// Limitation: the claim pointer must *exactly* be called "claim_ptr"
- bd_link_disk_holder(bde, vdisk)
+ bd_claim_by_disk(bde, claim_ptr, vdisk)
|
- bd_unlink_disk_holder(bde, vdisk)
+ bd_release_from_disk(bde, vdisk)
)
