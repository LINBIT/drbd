@@
expression dst, nla, maxlen;
@@
-nla_strscpy(dst, nla, maxlen)
+nla_strlcpy(dst, nla, maxlen)
