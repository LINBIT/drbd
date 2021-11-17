@@
@@
struct dtr_cm {
+      struct ib_mr *dma_mr;
       ...
};

@@
identifier kref, destroy_id, cm;
@@
static void __dtr_destroy_cm(struct kref *kref, bool destroy_id)
{
	struct dtr_cm *cm = container_of(kref, struct dtr_cm, kref);

+	if (cm->dma_mr) {
+		ib_dereg_mr(cm->dma_mr);
+		cm->dma_mr = NULL;
+	}
	...
}

@@
identifier cm;
type u32;
@@
static u32 dtr_cm_to_lkey(struct dtr_cm *cm)
{
+	return cm->dma_mr->lkey;
-	return cm->pd->local_dma_lkey;
}

@@
identifier cm, cause, i, path;
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
		dtr_create_rx_desc(&path->flow[i]);

	return 0;
	...
}
