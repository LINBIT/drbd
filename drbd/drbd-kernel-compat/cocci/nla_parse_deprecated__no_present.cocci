// Note: this is basically the spatch from the original upstream commit,
// but reversed.

@@
expression TB, MAX, HEAD, LEN, POL, EXT;
@@
-nla_parse_deprecated(TB, MAX, HEAD, LEN, POL, EXT)
+nla_parse(TB, MAX, HEAD, LEN, POL, EXT)

@@
expression NLH, HDRLEN, TB, MAX, POL, EXT;
@@
-nlmsg_parse_deprecated(NLH, HDRLEN, TB, MAX, POL, EXT)
+nlmsg_parse(NLH, HDRLEN, TB, MAX, POL, EXT)

@@
expression NLH, HDRLEN, TB, MAX, POL, EXT;
@@
-nlmsg_parse_deprecated_strict(NLH, HDRLEN, TB, MAX, POL, EXT)
+nlmsg_parse_strict(NLH, HDRLEN, TB, MAX, POL, EXT)

@@
expression TB, MAX, NLA, POL, EXT;
@@
-nla_parse_nested_deprecated(TB, MAX, NLA, POL, EXT)
+nla_parse_nested(TB, MAX, NLA, POL, EXT)

@@
expression START, MAX, POL, EXT;
@@
-nla_validate_nested_deprecated(START, MAX, POL, EXT)
+nla_validate_nested(START, MAX, POL, EXT)

@@
expression NLH, HDRLEN, MAX, POL, EXT;
@@
-nlmsg_validate_deprecated(NLH, HDRLEN, MAX, POL, EXT)
+nlmsg_validate(NLH, HDRLEN, MAX, POL, EXT)
