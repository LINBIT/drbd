@ ib_get_dma_mr__struct @
@@
struct dtr_cm {
+      struct ib_mr *dma_mr;
       ...
};

@ ib_get_dma_mr__free @
identifier kref, destroy_id, cm, rdma_transport;
@@
static void __dtr_destroy_cm(struct kref *kref, bool destroy_id)
{
	struct dtr_cm *cm = container_of(kref, struct dtr_cm, kref);
	struct dtr_transport *rdma_transport = cm->rdma_transport;

+	if (cm->dma_mr) {
+		ib_dereg_mr(cm->dma_mr);
+		cm->dma_mr = NULL;
+	}
	...
}

@ ib_get_dma_mr__deref @
identifier cm;
type u32;
@@
static u32 dtr_cm_to_lkey(struct dtr_cm *cm)
{
+	return cm->dma_mr->lkey;
-	return cm->pd->local_dma_lkey;
}

@ ib_get_dma_mr__alloc @
identifier cm, cause, i;
@@
static int _dtr_cm_alloc_rdma_res(struct dtr_cm *cm,
				    enum dtr_alloc_rdma_res_causes *cause)
{
	...
+	/* create RDMA memory region (MR) */
+	cm->dma_mr = ib_get_dma_mr(cm->pd,
+			IB_ACCESS_LOCAL_WRITE |
+			IB_ACCESS_REMOTE_READ |
+			IB_ACCESS_REMOTE_WRITE);
+	if (IS_ERR(cm->dma_mr)) {
+		*cause = IB_GET_DMA_MR;
+		err = PTR_ERR(cm->dma_mr);
+		cm->dma_mr = NULL;
+
+		rdma_destroy_qp(cm->id);
+		goto createqp_failed;
+	}
+
	for (i = DATA_STREAM; i <= CONTROL_STREAM ; i++)
		dtr_create_rx_desc(...);

	return 0;
	...
}

@ script:python depends on !ib_get_dma_mr__struct || !ib_get_dma_mr__free || !ib_get_dma_mr__deref || !ib_get_dma_mr__alloc @
@@
import sys
print('ERROR: A rule making an essential change was not executed!', file=sys.stderr)
print('ERROR: This would not show up as a compiler error, but would still break DRBD.', file=sys.stderr)
print('ERROR: Check ib_get_dma_mr__yes_present.cocci', file=sys.stderr)
print('ERROR: As a precaution, the build will be aborted here.', file=sys.stderr)
sys.exit(1)
