@@
typedef atomic_t;
@@
+/* ATTENTION: this is a compat implementation of generic_*_io_acct,
+ * added by a coccinelle patch.
+ * it is more likely to be broken than the upstream version is.
+ */
+static inline void generic_start_io_acct(struct request_queue *q,
+		int rw, unsigned long sects, struct hd_struct *part)
+{
+	int cpu;
+
+	cpu = part_stat_lock();
+	part_round_stats(cpu, part);
+	part_stat_inc(cpu, part, ios[rw]);
+	part_stat_add(cpu, part, sectors[rw], sects);
+	(void) cpu; /* The macro invocations above want the cpu argument, I do not like
+		       the compiler warning about cpu only assigned but never used... */
+	/* part_inc_in_flight(part, rw); */
+	{ BUILD_BUG_ON(sizeof(atomic_t) != sizeof(part->in_flight[0])); }
+	atomic_inc((atomic_t*)&part->in_flight[rw]);
+	part_stat_unlock();
+}
+
+static inline void generic_end_io_acct(struct request_queue *q,
+		int rw, struct hd_struct *part, unsigned long start_time)
+{
+	unsigned long duration = jiffies - start_time;
+	int cpu;
+
+	cpu = part_stat_lock();
+	part_stat_add(cpu, part, ticks[rw], duration);
+	part_round_stats(cpu, part);
+	/* part_dec_in_flight(part, rw); */
+	atomic_dec((atomic_t*)&part->in_flight[rw]);
+	part_stat_unlock();
+}

drbd_req_new(...) { ... }
