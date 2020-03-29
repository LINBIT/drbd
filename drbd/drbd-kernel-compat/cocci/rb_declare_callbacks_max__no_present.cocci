@@
typedef sector_t;
@@
-#define NODE_END(...) (...)
+/**
+ * compute_subtree_last  -  compute end of @node
+ *
+ * The end of an interval is the highest (start + (size >> 9)) value of this
+ * node and of its children.  Called for @node and its parents whenever the end
+ * may have changed.
+ */
+static inline sector_t
+compute_subtree_last(struct drbd_interval *node)
+{
+       sector_t max = node->sector + (node->size >> 9);
+
+       if (node->rb.rb_left) {
+               sector_t left = interval_end(node->rb.rb_left);
+               if (left > max)
+                       max = left;
+       }
+       if (node->rb.rb_right) {
+               sector_t right = interval_end(node->rb.rb_right);
+               if (right > max)
+                       max = right;
+       }
+       return max;
+}

@@
declarer name RB_DECLARE_CALLBACKS_MAX;
declarer name RB_DECLARE_CALLBACKS;
@@
-RB_DECLARE_CALLBACKS_MAX
+RB_DECLARE_CALLBACKS
 (...,
- NODE_END
+ compute_subtree_last
 );
