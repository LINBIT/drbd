@@
expression sk;
@@
- sk_set_nospace(sk);
+ if (sk->sk_socket)
+ 	set_bit(SOCK_NOSPACE, &sk->sk_socket->flags);
