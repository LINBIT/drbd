// Before v6.1 struct genl_family has no resv_start_op. Those kernels do not
// substitute a reject-all policy for the dump ops either, so there is nothing
// to suppress.
@@
symbol drbd_nl_family;
attribute name __ro_after_init;
expression E;
@@
  struct genl_family drbd_nl_family __ro_after_init = {
  ...,
- .resv_start_op	= E,
  ...,
  };
