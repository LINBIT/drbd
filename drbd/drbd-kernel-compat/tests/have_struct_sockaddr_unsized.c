/* { "version": "v6.18-rc4", "commit": "bf33247a90d3e85d53a9b55bb276b725456ff0bf", "comment": "struct sockaddr_unsized was introduced", "author": "Kees Cook <kees@kernel.org>", "date": "Mon Nov 3 16:26:09 2025 -0800" } */

#include <linux/socket.h>

struct sockaddr_unsized x;
