@@
identifier fn;
identifier ops;
symbol skb, info;
@@
 int fn(
-const struct genl_split_ops *ops,
+const struct genl_ops *ops,
 struct sk_buff *skb, struct genl_info *info)
 { ... }

@@
identifier fn;
identifier ops;
symbol skb, info;
@@
 void fn(
-const struct genl_split_ops *ops,
+const struct genl_ops *ops,
 struct sk_buff *skb, struct genl_info *info)
 { ... }
