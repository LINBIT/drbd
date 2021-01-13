@ add_double_check @
type T;
identifier x;
statement S;
@@
+static int __init double_check_for_kabi_breakage(void)
+{
+#if defined(RHEL_RELEASE_CODE) && ((RHEL_RELEASE_CODE & 0xff00) == 0x700)
+	/* RHEL 7.5 chose to change sizeof(struct nla_policy), and to
+	 * lie about that, which makes the module version magic believe
+	 * it was compatible, while it is not.  To avoid "surprises" in
+	 * nla_parse() later, we ask the running kernel about its
+	 * opinion about the nla_policy_len() of this dummy nla_policy,
+	 * and if it does not agree, we fail on module load already. */
+	static struct nla_policy dummy[] = {
+		[0] = { .type = NLA_UNSPEC, .len =   8, },
+		[1] = { .type = NLA_UNSPEC, .len =  80, },
+		[2] = { .type = NLA_UNSPEC, .len = 800, },
+		[9] = { .type = NLA_UNSPEC, },
+	};
+	int len = nla_policy_len(dummy, 3);
+	if (len != 900) {
+		pr_notice("kernel disagrees about the layout of struct nla_policy (%d)\n", len);
+		pr_err("kABI breakage detected! module compiled for: %s\n", UTS_RELEASE);
+		return -EINVAL;
+	}
+#endif
+	return 0;
+}
+
drbd_init(...)
{
...
}

@ call_double_check depends on ever add_double_check @
symbol err;
@@
// it would be much more logical to do something like:
//
// drbd_init(...)
// {
//	...
//	T x;
//	+ if(double_check...)
// 	...
// }
//
// but for whatever reason, spatch does not want to match inside the drbd_init
// function here. apparently it has something to do with the #ifdef MODULE
// a few lines below.
// so just chuck our call inbetween two known statements in that function and
// hope that it matches the right thing.
int err;
+ if (double_check_for_kabi_breakage())
+	return -EINVAL;
initialize_kref_debugging();

@ add_vermagic_h depends on ever add_double_check && file in "drbd_main.c" @
@@
 #include <...>
+ #include <linux/vermagic.h>
