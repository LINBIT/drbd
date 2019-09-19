/// Make sure the bitops on drbd_xxx->flags are only used with the right enums
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

@drbd_flag_ops@
constant F;
type T;
T *var;
position p;
@@
(
	test_bit(F, &var->flags)@p
|
	set_bit(F, &var->flags)@p
|
	clear_bit(F, &var->flags)@p
|
	test_and_set_bit(F, &var->flags)@p
|
	test_and_set_bit(F, &var->flags)@p
)

@script:python depends on report@
t << drbd_flag_ops.T;
f << drbd_flag_ops.F;
p << drbd_flag_ops.p;
@@
if t.startswith("struct drbd_"):
    enum_name = t[12:] + "_flag";
    if enum_name in enums and not f in enums[enum_name]:
        msg = "ERROR: %s used as enum value on %s but it is not a %s" % (f, t, enum_name)
        coccilib.report.print_report(p[0], msg)
