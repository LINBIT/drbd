@@
expression flags;
@@
  flags
- | MSG_SPLICE_PAGES

@@
identifier bvec, page, len, offset, msg, socket;
identifier sent = sent;
@@
- struct bio_vec bvec;
  ...
  int sent;
- bvec_set_page(&bvec, page, len, offset);
- iov_iter_bvec(&msg.msg_iter, ITER_SOURCE, &bvec, 1, len);
- sent = sock_sendmsg(socket, &msg);
+ sent = socket->ops->sendpage(socket, page, offset, len, msg.msg_flags);
