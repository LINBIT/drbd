@@
@@
(
- timer_shutdown
+ del_timer
 (...)
|
- timer_shutdown_sync
+ del_timer_sync
 (...)
)

// dtr_free() shuts the control timer down. With del_timer_sync() in its
// place, a late dtr_set_rcvtimeo() may re-arm it; never re-initialize a
// pending timer.
@@
expression E;
identifier fn;
@@
dtr_prepare_connect(...)
{
...
+ del_timer_sync(&E->control_timer);
timer_setup(&E->control_timer, fn, 0);
...
}
