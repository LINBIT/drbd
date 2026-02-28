@@
identifier fn;
identifier ops;
@@
 int fn(
-const struct genl_split_ops *ops,
+const struct genl_ops *ops,
 struct sk_buff *skb, struct genl_info *info)
 { ... }

@@
identifier fn;
identifier ops;
@@
 void fn(
-const struct genl_split_ops *ops,
+const struct genl_ops *ops,
 struct sk_buff *skb, struct genl_info *info)
 { ... }
