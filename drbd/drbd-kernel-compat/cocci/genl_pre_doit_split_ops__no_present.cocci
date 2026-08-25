// Before v6.2 there is no struct genl_split_ops; genl_family.pre_doit and
// .post_doit take a struct genl_ops instead. The generated ops table is a
// plain genl_ops table either way, so only the hook signatures differ.
@@
@@
-struct genl_split_ops
+struct genl_ops
