@@
expression fam, skb, portid, group;
@@
-return genlmsg_multicast_allns(fam, skb, portid, group);
+int ret;
+rcu_read_lock();
+ret = genlmsg_multicast_allns(fam, skb, portid, group, GFP_ATOMIC);
+rcu_read_unlock();
+return ret;
