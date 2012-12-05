#ifndef __WRAP_PRINTF
#define __WRAP_PRINTF

extern int wrap_printf(int indent, const char *format, ...)
	__attribute__((format(printf, 2, 3)));
extern int wrap_printf_wordwise(int indent, const char *str);

#endif  /* __WRAP_PRINTF */
