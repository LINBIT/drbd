@@
expression Q, S;
identifier fn, swr;
@@
fn(...)
{
...
- const struct ib_send_wr *swr;
+ struct ib_send_wr *swr;
...
ib_post_send(Q, S, &swr)
...
}


@@
expression Q, S;
identifier fn, rwr;
@@
fn(...)
{
...
- const struct ib_recv_wr *rwr;
+ struct ib_recv_wr *rwr;
...
ib_post_recv(Q, S, &rwr)
...
}
