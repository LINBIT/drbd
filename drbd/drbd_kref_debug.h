#ifndef DRBD_KREF_DEBUG_H
#define DRBD_KREF_DEBUG_H

#include <kref_debug.h>

#ifdef CONFIG_KREF_DEBUG
extern struct kref_debug_class kref_class_resource;
extern struct kref_debug_class kref_class_connection;
extern struct kref_debug_class kref_class_device;
#endif

#endif
