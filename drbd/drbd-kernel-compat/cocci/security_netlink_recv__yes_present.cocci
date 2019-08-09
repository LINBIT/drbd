@@
expression CAP;
identifier sk;
identifier fn;
@@
fn (...,
    struct sk_buff *sk,
    ...)
{
...
- !capable(CAP)
+ security_netlink_recv(sk, CAP)
...
}
