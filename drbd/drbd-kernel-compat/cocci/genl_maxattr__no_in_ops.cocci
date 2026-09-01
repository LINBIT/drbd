// Before v5.10 (48526a0f4ca2) struct genl_ops has no .maxattr; the top-level
// attribute count lives in struct genl_family only.

// Remove .maxattr from genl_ops entries. Anchor on .cmd to only match ops
// entries, not the family struct.
@@
expression E1, E2;
@@
  {
  .cmd = E1,
  ...,
- .maxattr = E2,
  ...,
  }

// Set the family-level maximum instead. handshake_nl_family already carries
// its .maxattr unconditionally.
@@
symbol drbd_nl_family, true;
attribute name __ro_after_init;
@@
  struct genl_family drbd_nl_family __ro_after_init = {
  ...,
  .parallel_ops = true,
+ .maxattr = DRBD_NLA_MAX,
  };

// Take the max attribute of drbd_pre_doit()'s mandatory-bit check from the
// family instead of the per-command ops.
@@
expression ops;
@@
- ops->maxattr
+ DRBD_NLA_MAX
