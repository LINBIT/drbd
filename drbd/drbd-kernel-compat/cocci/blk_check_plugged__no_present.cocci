@@
@@
-struct drbd_plug_cb {
-...
-};

@@
@@
-void drbd_unplug(...)
-{
-...
-}

@@
@@
-struct drbd_plug_cb* drbd_check_plugged(...)
-{
-...
-}

@@
@@
-void drbd_update_plug(...)
-{
-...
-}

@@
identifier pl;
@@
-if(...) {
-	struct drbd_plug_cb *pl = ...;
-	if(pl) {
-		...
-	}
-}
