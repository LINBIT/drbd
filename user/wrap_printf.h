#ifndef __WRAP_PRINTF
#define __WRAP_PRINTF

extern int wrap_printf(int indent, char *format, ...) __attribute__((format(printf, 2, 3)));

#endif  /* __WRAP_PRINTF */
