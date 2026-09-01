/// Make sure the bitops on a drbd flags field are only used with the right enums
//
// Options: --include-headers

virtual report

@initialize:python@
@@
enums = {}

@find_enums@
identifier id =~ "(device|peer_device|connection|resource)_flag";
identifier c;
@@
	enum id { ..., c , ... }

@script:python@
id << find_enums.id;
c << find_enums.c;
@@
if id in enums:
    enums[id].append(c)
else:
    enums[id] = [c]

// Match on the object holding the flags rather than on a pointer to it. A peer
// meta-data slot is usually reached through the peers[] array in struct
// drbd_md, so there is no pointer to match on. The standard isomorphisms equate
// E->f with (*E).f, so this covers the accesses through a pointer as well.
//
// .flags is matched both as &var.flags (scalar unsigned long) and as var.flags
// (an unsigned long bitmap array that decays to the pointer the bitops want).
// peer_device uses the array form, the other objects the scalar.
@drbd_flag_ops@
constant F;
type T;
T var;
position p;
@@
(
	test_bit(F, &var.flags)@p
|
	test_bit(F, var.flags)@p
|
	set_bit(F, &var.flags)@p
|
	set_bit(F, var.flags)@p
|
	clear_bit(F, &var.flags)@p
|
	clear_bit(F, var.flags)@p
|
	test_and_set_bit(F, &var.flags)@p
|
	test_and_set_bit(F, var.flags)@p
|
	test_and_clear_bit(F, &var.flags)@p
|
	test_and_clear_bit(F, var.flags)@p
)

@script:python depends on report@
t << drbd_flag_ops.T;
f << drbd_flag_ops.F;
p << drbd_flag_ops.p;
@@
if t == "struct drbd_peer_md":
    # enum mdf_peer_flag_bit gives every member an explicit value, which
    # find_enums does not match, so go by the prefix its members share.
    if not f.startswith("__MDF_"):
        msg = "ERROR: %s used as enum value on %s but it is not a mdf_peer_flag_bit" % (f, t)
        coccilib.report.print_report(p[0], msg)
elif t.startswith("struct drbd_"):
    enum_name = t[12:] + "_flag";
    if enum_name in enums and not f in enums[enum_name]:
        msg = "ERROR: %s used as enum value on %s but it is not a %s" % (f, t, enum_name)
        coccilib.report.print_report(p[0], msg)
