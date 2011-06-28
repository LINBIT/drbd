#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>

int wrap_printf(int indent, char *format, ...)
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
