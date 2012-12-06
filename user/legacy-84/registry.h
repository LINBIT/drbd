#ifndef __REGISTRY_H
#define __REGISTRY_H

extern int register_minor(int minor, const char *path);
extern int unregister_minor(int minor);
extern char *lookup_minor(int minor);
extern int unregister_resource(const char *name);
extern int register_resource(const char *name, const char *path);
extern char *lookup_resource(const char *name);

#endif  /* __REGISTRY_H */
