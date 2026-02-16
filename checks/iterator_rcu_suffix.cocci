// Ensure that the correct _rcu variants are used on iterators when appropriate

virtual report

@ r exists @
iterator it =~ "for_each_(peer_device|connection|resource)$";
position p;
@@
rcu_read_lock();
<+...
it(...)@p{
	...
}
...+>
rcu_read_unlock();

@script:python depends on report@
p << r.p;
it << r.it;
@@
msg = "ERROR: %s without rcu suffix used in rcu context" % (it)
coccilib.report.print_report(p[0], msg)
