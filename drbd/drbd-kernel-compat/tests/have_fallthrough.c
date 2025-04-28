/* { "version": "v5.4-rc3", "commit": "294f69e662d1570703e9b56e95be37a9fd3afba5", "comment": "The fallthrough pseudo-statement was added in v5.4-rc3", "author": "Joe Perches <joe@perches.com>", "date": "Sat Oct 5 09:46:42 2019 -0700" } */

#include <linux/compiler_attributes.h>

int foo(int i); /* Avoid warning about missing function prototype */
int foo(int i)
{
	int y = 0;

	switch(i) {
	case 0:
		fallthrough;
	case 1:
		y = i;
	}

	return y;
}
