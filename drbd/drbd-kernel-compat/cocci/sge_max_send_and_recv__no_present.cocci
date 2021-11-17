@@
struct ib_device_attr dev_attr;
@@
-min(dev_attr.max_send_sge, dev_attr.max_recv_sge)
+dev_attr.max_sge
