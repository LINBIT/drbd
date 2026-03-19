/* { "version": "v6.13-rc1", "commit": "4138e9ec00936c9fe7d0fe961e32f381b1e36926", "comment": "netlink: add NLA_POLICY_MAX_LEN macro", "author": "Antonio Quartulli <antonio@openvpn.net>", "date": "Tue Oct 29 11:47:14 2024 +0100" } */
#include <net/netlink.h>

struct nla_policy p = NLA_POLICY_MAX_LEN(128);
