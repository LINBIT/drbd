/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __DRBD_NLA_H
#define __DRBD_NLA_H

int drbd_nla_parse_nested(struct nlattr *tb[], int maxtype,
			  struct nlattr *nla, const struct nla_policy *policy);
struct nlattr *drbd_nla_find_nested(int maxtype, struct nlattr *nla,
				    int attrtype);

#endif  /* __DRBD_NLA_H */
