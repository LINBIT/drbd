@@
expression bit, addr, value;
@@
-assign_bit(bit, addr, value);
+if (value)
+	set_bit(bit, addr);
+else
+	clear_bit(bit, addr);
