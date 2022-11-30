@@
identifier skb, attrtype, value;
@@
- nla_put_64bit(skb, attrtype, ..., &value, ...)
+ nla_put_u64(skb, attrtype, value)
