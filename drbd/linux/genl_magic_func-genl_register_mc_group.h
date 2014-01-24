#undef GENL_mc_group
#define GENL_mc_group(group)						\
static struct genl_multicast_group					\
CONCAT_(GENL_MAGIC_FAMILY, _mcg_ ## group) __read_mostly = {		\
	.name = #group,							\
};									\
static int CONCAT_(GENL_MAGIC_FAMILY, _genl_multicast_ ## group)(	\
	struct sk_buff *skb, gfp_t flags)				\
{									\
	unsigned int group_id =						\
		CONCAT_(GENL_MAGIC_FAMILY, _mcg_ ## group).id;	\
	if (!group_id)							\
		return -EINVAL;						\
	return genlmsg_multicast(skb, 0, group_id, flags);		\
}

#include GENL_MAGIC_INCLUDE_FILE

int CONCAT_(GENL_MAGIC_FAMILY, _genl_register)(void)
{
	int err = genl_register_family_with_ops(&ZZZ_genl_family,
		ZZZ_genl_ops, ARRAY_SIZE(ZZZ_genl_ops));
	if (err)
		return err;
#undef GENL_mc_group
#define GENL_mc_group(group)						\
	err = genl_register_mc_group(&ZZZ_genl_family,			\
		&CONCAT_(GENL_MAGIC_FAMILY, _mcg_ ## group));		\
	if (err)							\
		goto fail;						\
	else								\
		pr_info("%s: mcg %s: %u\n", #group,			\
			__stringify(GENL_MAGIC_FAMILY),			\
			CONCAT_(GENL_MAGIC_FAMILY, _mcg_ ## group).id);

#include GENL_MAGIC_INCLUDE_FILE

#undef GENL_mc_group
#define GENL_mc_group(group)
	return 0;
fail:
	genl_unregister_family(&ZZZ_genl_family);
	return err;
}

void CONCAT_(GENL_MAGIC_FAMILY, _genl_unregister)(void)
{
	genl_unregister_family(&ZZZ_genl_family);
}
