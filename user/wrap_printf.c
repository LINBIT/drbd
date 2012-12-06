#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>

int wrap_printf(int indent, const char *format, ...)
{
	static int columns, col;
	va_list ap1, ap2;
	int n;
	const char *nl;

	if (columns == 0) {
		struct winsize ws = { };

		ioctl(1, TIOCGWINSZ, &ws);
		columns = ws.ws_col;
		if (columns <= 0)
			columns = 80;
	}

	va_start(ap1, format);
	va_copy(ap2, ap1);
	n = vsnprintf(NULL, 0, format, ap1);
	va_end(ap1);
	if (col + n > columns) {
		putchar('\n');
		if (*format == '\n')
			format++;
		col = 0;
	}
	if (col == 0) {
		while (*format == ' ')
			format++;
		col += indent;
		while (indent--)
			putchar(' ');
	}
	n = vprintf(format, ap2);
	va_end(ap2);
	if (n > 0)
		col += n;

	nl = strrchr(format, '\n');
	if (nl && nl[1] == 0)
		col = 0;

	return n;
}

int wrap_printf_wordwise(int indent, const char *str)
{
	int n = 0;

	do {
		const char *fmt = "%.*s", *s;
		int m;

		if (*str == ' ') {
			fmt = " %.*s";
			while (*str == ' ')
				str++;
		}
		for (s = str; *s && *s != ' '; s++)
			/* nothing */ ;
		m = wrap_printf(indent, fmt, s - str, str);
		if (m < 0)
			return m;
		n += m;
		str = s;
	} while (*str);

	return n;
}
