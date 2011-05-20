#ifndef LIBGENL_H
#define LIBGENL_H

/*
 * stripped down copy of
 * linux-2.6.32/include/net/netlink.h and
 * linux-2.6.32/include/net/genetlink.h
 *
 * sk_buff -> "msg_buff"
 */

#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/socket.h>
#include <linux/socket.h>
#include <linux/types.h>
#include <linux/netlink.h>
#include <linux/genetlink.h>

#ifndef SOL_NETLINK
#define SOL_NETLINK 270
#endif

#define DEBUG_LEVEL 1

#define dbg(lvl, fmt, arg...)				\
do {							\
	if (lvl <= DEBUG_LEVEL)				\
		fprintf(stderr, "<%d>" fmt "\n",	\
				lvl , ##arg);		\
} while (0)

#define BUG_ON(cond)						\
	do {							\
		int __cond = (cond);				\
		if (!__cond)					\
			break;					\
		fprintf(stderr, "BUG: %s:%d: %s == %u\n",	\
				__FILE__, __LINE__,		\
				#cond, __cond);			\
		abort();				\
	} while (0)

#define min_t(type, x, y) ({                    \
        type __min1 = (x);                      \
        type __min2 = (y);                      \
        __min1 < __min2 ? __min1: __min2; })

#ifndef __unused
#define __unused __attribute((unused))
#endif

#ifndef __read_mostly
#define __read_mostly
#endif

#ifndef unlikely
#define unlikely(arg) (arg)
#endif

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#endif


struct msg_buff {
	/* housekeeping */
	unsigned char *tail;
	unsigned char *end;
	/* start of data to be send(),
	 * or received into */
	unsigned char data[0];
};

#define DEFAULT_MSG_SIZE	8192

static inline int msg_tailroom(struct msg_buff *msg)
{
	return msg->end - msg->tail;
}

static inline struct msg_buff *msg_new(size_t size)
{
	struct msg_buff *m = calloc(1, sizeof(*m) + size);
	if (!m)
		return NULL;

	m->tail = m->data;
	m->end  = m->tail + size;

	return m;
}

static inline void msg_free(struct msg_buff *m)
{
	free(m);
}

static inline void *msg_put(struct msg_buff *msg, unsigned int len)
{
	void *tmp = msg->tail;
	msg->tail += len;
	BUG_ON(msg->tail > msg->end);
	return (void*)tmp;
}

/* ========================================================================
 *         Netlink Messages and Attributes Interface (As Seen On TV)
 * ------------------------------------------------------------------------
 *                          Messages Interface
 * ------------------------------------------------------------------------
 *
 * Message Format:
 *    <--- nlmsg_total_size(payload)  --->
 *    <-- nlmsg_msg_size(payload) ->
 *   +----------+- - -+-------------+- - -+-------- - -
 *   | nlmsghdr | Pad |   Payload   | Pad | nlmsghdr
 *   +----------+- - -+-------------+- - -+-------- - -
 *   nlmsg_data(nlh)---^                   ^
 *   nlmsg_next(nlh)-----------------------+
 *
 * Payload Format:
 *    <---------------------- nlmsg_len(nlh) --------------------->
 *    <------ hdrlen ------>       <- nlmsg_attrlen(nlh, hdrlen) ->
 *   +----------------------+- - -+--------------------------------+
 *   |     Family Header    | Pad |           Attributes           |
 *   +----------------------+- - -+--------------------------------+
 *   nlmsg_attrdata(nlh, hdrlen)---^
 *
 * Data Structures:
 *   struct nlmsghdr			netlink message header
 *
 * Message Construction:
 *   nlmsg_new()			create a new netlink message
 *   nlmsg_put()			add a netlink message to an msg
 *   nlmsg_put_answer()			callback based nlmsg_put()
 *   nlmsg_end()			finanlize netlink message
 *   nlmsg_get_pos()			return current position in message
 *   nlmsg_trim()			trim part of message
 *   nlmsg_cancel()			cancel message construction
 *   nlmsg_free()			free a netlink message
 *
 * Message Sending:
 *   nlmsg_multicast()			multicast message to several groups
 *   nlmsg_unicast()			unicast a message to a single socket
 *   nlmsg_notify()			send notification message
 *
 * Message Length Calculations:
 *   nlmsg_msg_size(payload)		length of message w/o padding
 *   nlmsg_total_size(payload)		length of message w/ padding
 *   nlmsg_padlen(payload)		length of padding at tail
 *
 * Message Payload Access:
 *   nlmsg_data(nlh)			head of message payload
 *   nlmsg_len(nlh)			length of message payload
 *   nlmsg_attrdata(nlh, hdrlen)	head of attributes data
 *   nlmsg_attrlen(nlh, hdrlen)		length of attributes data
 *
 * Message Parsing:
 *   nlmsg_ok(nlh, remaining)		does nlh fit into remaining bytes?
 *   nlmsg_next(nlh, remaining)		get next netlink message
 *   nlmsg_parse()			parse attributes of a message
 *   nlmsg_find_attr()			find an attribute in a message
 *   nlmsg_for_each_msg()		loop over all messages
 *   nlmsg_validate()			validate netlink message incl. attrs
 *   nlmsg_for_each_attr()		loop over all attributes
 *
 * Misc:
 *   nlmsg_report()			report back to application?
 *
 * ------------------------------------------------------------------------
 *                          Attributes Interface
 * ------------------------------------------------------------------------
 *
 * Attribute Format:
 *    <------- nla_total_size(payload) ------->
 *    <---- nla_attr_size(payload) ----->
 *   +----------+- - -+- - - - - - - - - +- - -+-------- - -
 *   |  Header  | Pad |     Payload      | Pad |  Header
 *   +----------+- - -+- - - - - - - - - +- - -+-------- - -
 *                     <- nla_len(nla) ->      ^
 *   nla_data(nla)----^                        |
 *   nla_next(nla)-----------------------------'
 *
 * Data Structures:
 *   struct nlattr			netlink attribute header
 *
 * Attribute Construction:
 *   nla_reserve(msg, type, len)	reserve room for an attribute
 *   nla_reserve_nohdr(msg, len)	reserve room for an attribute w/o hdr
 *   nla_put(msg, type, len, data)	add attribute to msg
 *   nla_put_nohdr(msg, len, data)	add attribute w/o hdr
 *   nla_append(msg, len, data)		append data to msg
 *
 * Attribute Construction for Basic Types:
 *   nla_put_u8(msg, type, value)	add u8 attribute to msg
 *   nla_put_u16(msg, type, value)	add u16 attribute to msg
 *   nla_put_u32(msg, type, value)	add u32 attribute to msg
 *   nla_put_u64(msg, type, value)	add u64 attribute to msg
 *   nla_put_string(msg, type, str)	add string attribute to msg
 *   nla_put_flag(msg, type)		add flag attribute to msg
 *   nla_put_msecs(msg, type, jiffies)	add msecs attribute to msg
 *
 * Exceptions Based Attribute Construction:
 *   NLA_PUT(msg, type, len, data)	add attribute to msg
 *   NLA_PUT_U8(msg, type, value)	add u8 attribute to msg
 *   NLA_PUT_U16(msg, type, value)	add u16 attribute to msg
 *   NLA_PUT_U32(msg, type, value)	add u32 attribute to msg
 *   NLA_PUT_U64(msg, type, value)	add u64 attribute to msg
 *   NLA_PUT_STRING(msg, type, str)	add string attribute to msg
 *   NLA_PUT_FLAG(msg, type)		add flag attribute to msg
 *   NLA_PUT_MSECS(msg, type, jiffies)	add msecs attribute to msg
 *
 *   The meaning of these functions is equal to their lower case
 *   variants but they jump to the label nla_put_failure in case
 *   of a failure.
 *
 * Nested Attributes Construction:
 *   nla_nest_start(msg, type)		start a nested attribute
 *   nla_nest_end(msg, nla)		finalize a nested attribute
 *   nla_nest_cancel(msg, nla)		cancel nested attribute construction
 *
 * Attribute Length Calculations:
 *   nla_attr_size(payload)		length of attribute w/o padding
 *   nla_total_size(payload)		length of attribute w/ padding
 *   nla_padlen(payload)		length of padding
 *
 * Attribute Payload Access:
 *   nla_data(nla)			head of attribute payload
 *   nla_len(nla)			length of attribute payload
 *
 * Attribute Payload Access for Basic Types:
 *   nla_get_u8(nla)			get payload for a u8 attribute
 *   nla_get_u16(nla)			get payload for a u16 attribute
 *   nla_get_u32(nla)			get payload for a u32 attribute
 *   nla_get_u64(nla)			get payload for a u64 attribute
 *   nla_get_flag(nla)			return 1 if flag is true
 *   nla_get_msecs(nla)			get payload for a msecs attribute
 *
 * Attribute Misc:
 *   nla_memcpy(dest, nla, count)	copy attribute into memory
 *   nla_memcmp(nla, data, size)	compare attribute with memory area
 *   nla_strlcpy(dst, nla, size)	copy attribute to a sized string
 *   nla_strcmp(nla, str)		compare attribute with string
 *
 * Attribute Parsing:
 *   nla_ok(nla, remaining)		does nla fit into remaining bytes?
 *   nla_next(nla, remaining)		get next netlink attribute
 *   nla_validate()			validate a stream of attributes
 *   nla_validate_nested()		validate a stream of nested attributes
 *   nla_find()				find attribute in stream of attributes
 *   nla_find_nested()			find attribute in nested attributes
 *   nla_parse()			parse and validate stream of attrs
 *   nla_parse_nested()			parse nested attribuets
 *   nla_for_each_attr()		loop over all attributes
 *   nla_for_each_nested()		loop over the nested attributes
 *=========================================================================
 */

 /**
  * Standard attribute types to specify validation policy
  */
enum {
	NLA_UNSPEC,
	NLA_U8,
	NLA_U16,
	NLA_U32,
	NLA_U64,
	NLA_STRING,
	NLA_FLAG,
	NLA_MSECS,
	NLA_NESTED,
	NLA_NESTED_COMPAT,
	NLA_NUL_STRING,
	NLA_BINARY,
	__NLA_TYPE_MAX,
};

#define NLA_TYPE_MAX (__NLA_TYPE_MAX - 1)

/**
 * struct nla_policy - attribute validation policy
 * @type: Type of attribute or NLA_UNSPEC
 * @len: Type specific length of payload
 *
 * Policies are defined as arrays of this struct, the array must be
 * accessible by attribute type up to the highest identifier to be expected.
 *
 * Meaning of `len' field:
 *    NLA_STRING           Maximum length of string
 *    NLA_NUL_STRING       Maximum length of string (excluding NUL)
 *    NLA_FLAG             Unused
 *    NLA_BINARY           Maximum length of attribute payload
 *    NLA_NESTED_COMPAT    Exact length of structure payload
 *    All other            Exact length of attribute payload
 *
 * Example:
 * static struct nla_policy my_policy[ATTR_MAX+1] __read_mostly = {
 * 	[ATTR_FOO] = { .type = NLA_U16 },
 *	[ATTR_BAR] = { .type = NLA_STRING, .len = BARSIZ },
 *	[ATTR_BAZ] = { .len = sizeof(struct mystruct) },
 * };
 */
struct nla_policy {
	__u16		type;
	__u16		len;
};

extern int		nla_validate(struct nlattr *head, int len, int maxtype,
				     const struct nla_policy *policy);
extern int		nla_parse(struct nlattr *tb[], int maxtype,
				  struct nlattr *head, int len,
				  const struct nla_policy *policy);
extern int		nla_policy_len(const struct nla_policy *, int);
extern struct nlattr *	nla_find(struct nlattr *head, int len, int attrtype);
extern size_t		nla_strlcpy(char *dst, const struct nlattr *nla,
				    size_t dstsize);
extern int		nla_memcpy(void *dest, const struct nlattr *src, int count);
extern int		nla_memcmp(const struct nlattr *nla, const void *data,
				   size_t size);
extern int		nla_strcmp(const struct nlattr *nla, const char *str);
extern struct nlattr *	__nla_reserve(struct msg_buff *msg, int attrtype,
				      int attrlen);
extern void *		__nla_reserve_nohdr(struct msg_buff *msg, int attrlen);
extern struct nlattr *	nla_reserve(struct msg_buff *msg, int attrtype,
				    int attrlen);
extern void *		nla_reserve_nohdr(struct msg_buff *msg, int attrlen);
extern void		__nla_put(struct msg_buff *msg, int attrtype,
				  int attrlen, const void *data);
extern void		__nla_put_nohdr(struct msg_buff *msg, int attrlen,
					const void *data);
extern int		nla_put(struct msg_buff *msg, int attrtype,
				int attrlen, const void *data);
extern int		nla_put_nohdr(struct msg_buff *msg, int attrlen,
				      const void *data);
extern int		nla_append(struct msg_buff *msg, int attrlen,
				   const void *data);

/**************************************************************************
 * Netlink Messages
 **************************************************************************/

/**
 * nlmsg_msg_size - length of netlink message not including padding
 * @payload: length of message payload
 */
static inline int nlmsg_msg_size(int payload)
{
	return NLMSG_HDRLEN + payload;
}

/**
 * nlmsg_total_size - length of netlink message including padding
 * @payload: length of message payload
 */
static inline int nlmsg_total_size(int payload)
{
	return NLMSG_ALIGN(nlmsg_msg_size(payload));
}

/**
 * nlmsg_padlen - length of padding at the message's tail
 * @payload: length of message payload
 */
static inline int nlmsg_padlen(int payload)
{
	return nlmsg_total_size(payload) - nlmsg_msg_size(payload);
}

/**
 * nlmsg_data - head of message payload
 * @nlh: netlink messsage header
 */
static inline void *nlmsg_data(const struct nlmsghdr *nlh)
{
	return (unsigned char *) nlh + NLMSG_HDRLEN;
}

/**
 * nlmsg_len - length of message payload
 * @nlh: netlink message header
 */
static inline int nlmsg_len(const struct nlmsghdr *nlh)
{
	return nlh->nlmsg_len - NLMSG_HDRLEN;
}

/**
 * nlmsg_attrdata - head of attributes data
 * @nlh: netlink message header
 * @hdrlen: length of family specific header
 */
static inline struct nlattr *nlmsg_attrdata(const struct nlmsghdr *nlh,
					    int hdrlen)
{
	unsigned char *data = nlmsg_data(nlh);
	return (struct nlattr *) (data + NLMSG_ALIGN(hdrlen));
}

/**
 * nlmsg_attrlen - length of attributes data
 * @nlh: netlink message header
 * @hdrlen: length of family specific header
 */
static inline int nlmsg_attrlen(const struct nlmsghdr *nlh, int hdrlen)
{
	return nlmsg_len(nlh) - NLMSG_ALIGN(hdrlen);
}

/**
 * nlmsg_ok - check if the netlink message fits into the remaining bytes
 * @nlh: netlink message header
 * @remaining: number of bytes remaining in message stream
 */
static inline int nlmsg_ok(const struct nlmsghdr *nlh, int remaining)
{
	return (remaining >= (int) sizeof(struct nlmsghdr) &&
		nlh->nlmsg_len >= sizeof(struct nlmsghdr) &&
		nlh->nlmsg_len <= (__u32)remaining);
}

/**
 * nlmsg_next - next netlink message in message stream
 * @nlh: netlink message header
 * @remaining: number of bytes remaining in message stream
 *
 * Returns the next netlink message in the message stream and
 * decrements remaining by the size of the current message.
 */
static inline struct nlmsghdr *nlmsg_next(struct nlmsghdr *nlh, int *remaining)
{
	int totlen = NLMSG_ALIGN(nlh->nlmsg_len);

	*remaining -= totlen;

	return (struct nlmsghdr *) ((unsigned char *) nlh + totlen);
}

/**
 * nlmsg_parse - parse attributes of a netlink message
 * @nlh: netlink message header
 * @hdrlen: length of family specific header
 * @tb: destination array with maxtype+1 elements
 * @maxtype: maximum attribute type to be expected
 * @policy: validation policy
 *
 * See nla_parse()
 */
static inline int nlmsg_parse(const struct nlmsghdr *nlh, int hdrlen,
			      struct nlattr *tb[], int maxtype,
			      const struct nla_policy *policy)
{
	if (nlh->nlmsg_len < (__u32)nlmsg_msg_size(hdrlen))
		return -EINVAL;

	return nla_parse(tb, maxtype, nlmsg_attrdata(nlh, hdrlen),
			 nlmsg_attrlen(nlh, hdrlen), policy);
}

/**
 * nlmsg_find_attr - find a specific attribute in a netlink message
 * @nlh: netlink message header
 * @hdrlen: length of familiy specific header
 * @attrtype: type of attribute to look for
 *
 * Returns the first attribute which matches the specified type.
 */
static inline struct nlattr *nlmsg_find_attr(struct nlmsghdr *nlh,
					     int hdrlen, int attrtype)
{
	return nla_find(nlmsg_attrdata(nlh, hdrlen),
			nlmsg_attrlen(nlh, hdrlen), attrtype);
}

/**
 * nlmsg_validate - validate a netlink message including attributes
 * @nlh: netlinket message header
 * @hdrlen: length of familiy specific header
 * @maxtype: maximum attribute type to be expected
 * @policy: validation policy
 */
static inline int nlmsg_validate(struct nlmsghdr *nlh, int hdrlen, int maxtype,
				 const struct nla_policy *policy)
{
	if (nlh->nlmsg_len < (__u32)nlmsg_msg_size(hdrlen))
		return -EINVAL;

	return nla_validate(nlmsg_attrdata(nlh, hdrlen),
			    nlmsg_attrlen(nlh, hdrlen), maxtype, policy);
}

/**
 * nlmsg_report - need to report back to application?
 * @nlh: netlink message header
 *
 * Returns 1 if a report back to the application is requested.
 */
static inline int nlmsg_report(const struct nlmsghdr *nlh)
{
	return !!(nlh->nlmsg_flags & NLM_F_ECHO);
}

/**
 * nlmsg_for_each_attr - iterate over a stream of attributes
 * @pos: loop counter, set to current attribute
 * @nlh: netlink message header
 * @hdrlen: length of familiy specific header
 * @rem: initialized to len, holds bytes currently remaining in stream
 */
#define nlmsg_for_each_attr(pos, nlh, hdrlen, rem) \
	nla_for_each_attr(pos, nlmsg_attrdata(nlh, hdrlen), \
			  nlmsg_attrlen(nlh, hdrlen), rem)

/**
 * nlmsg_for_each_msg - iterate over a stream of messages
 * @pos: loop counter, set to current message
 * @head: head of message stream
 * @len: length of message stream
 * @rem: initialized to len, holds bytes currently remaining in stream
 */
#define nlmsg_for_each_msg(pos, head, len, rem) \
	for (pos = head, rem = len; \
	     nlmsg_ok(pos, rem); \
	     pos = nlmsg_next(pos, &(rem)))

/**************************************************************************
 * Netlink Attributes
 **************************************************************************/

/**
 * nla_attr_size - length of attribute not including padding
 * @payload: length of payload
 */
static inline int nla_attr_size(int payload)
{
	return NLA_HDRLEN + payload;
}

/**
 * nla_total_size - total length of attribute including padding
 * @payload: length of payload
 */
static inline int nla_total_size(int payload)
{
	return NLA_ALIGN(nla_attr_size(payload));
}

/**
 * nla_padlen - length of padding at the tail of attribute
 * @payload: length of payload
 */
static inline int nla_padlen(int payload)
{
	return nla_total_size(payload) - nla_attr_size(payload);
}

/**
 * nla_type - attribute type
 * @nla: netlink attribute
 */
static inline int nla_type(const struct nlattr *nla)
{
	return nla->nla_type & NLA_TYPE_MASK;
}

/**
 * nla_data - head of payload
 * @nla: netlink attribute
 */
static inline void *nla_data(const struct nlattr *nla)
{
	return (char *) nla + NLA_HDRLEN;
}

/**
 * nla_len - length of payload
 * @nla: netlink attribute
 */
static inline int nla_len(const struct nlattr *nla)
{
	return nla->nla_len - NLA_HDRLEN;
}

/**
 * nla_ok - check if the netlink attribute fits into the remaining bytes
 * @nla: netlink attribute
 * @remaining: number of bytes remaining in attribute stream
 */
static inline int nla_ok(const struct nlattr *nla, int remaining)
{
	return remaining >= (int) sizeof(*nla) &&
	       nla->nla_len >= sizeof(*nla) &&
	       nla->nla_len <= remaining;
}

/**
 * nla_next - next netlink attribute in attribute stream
 * @nla: netlink attribute
 * @remaining: number of bytes remaining in attribute stream
 *
 * Returns the next netlink attribute in the attribute stream and
 * decrements remaining by the size of the current attribute.
 */
static inline struct nlattr *nla_next(const struct nlattr *nla, int *remaining)
{
	int totlen = NLA_ALIGN(nla->nla_len);

	*remaining -= totlen;
	return (struct nlattr *) ((char *) nla + totlen);
}

/**
 * nla_find_nested - find attribute in a set of nested attributes
 * @nla: attribute containing the nested attributes
 * @attrtype: type of attribute to look for
 *
 * Returns the first attribute which matches the specified type.
 */
static inline struct nlattr *nla_find_nested(struct nlattr *nla, int attrtype)
{
	return nla_find(nla_data(nla), nla_len(nla), attrtype);
}

/**
 * nla_parse_nested - parse nested attributes
 * @tb: destination array with maxtype+1 elements
 * @maxtype: maximum attribute type to be expected
 * @nla: attribute containing the nested attributes
 * @policy: validation policy
 *
 * See nla_parse()
 */
static inline int nla_parse_nested(struct nlattr *tb[], int maxtype,
				   const struct nlattr *nla,
				   const struct nla_policy *policy)
{
	return nla_parse(tb, maxtype, nla_data(nla), nla_len(nla), policy);
}

/**
 * nla_put_u8 - Add a u8 netlink attribute to a message buffer
 * @msg: message buffer to add attribute to
 * @attrtype: attribute type
 * @value: numeric value
 */
static inline int nla_put_u8(struct msg_buff *msg, int attrtype, __u8 value)
{
	return nla_put(msg, attrtype, sizeof(__u8), &value);
}

/**
 * nla_put_u16 - Add a u16 netlink attribute to a message buffer
 * @msg: message buffer to add attribute to
 * @attrtype: attribute type
 * @value: numeric value
 */
static inline int nla_put_u16(struct msg_buff *msg, int attrtype, __u16 value)
{
	return nla_put(msg, attrtype, sizeof(__u16), &value);
}

/**
 * nla_put_u32 - Add a u32 netlink attribute to a message buffer
 * @msg: message buffer to add attribute to
 * @attrtype: attribute type
 * @value: numeric value
 */
static inline int nla_put_u32(struct msg_buff *msg, int attrtype, __u32 value)
{
	return nla_put(msg, attrtype, sizeof(__u32), &value);
}

/**
 * nla_put_64 - Add a u64 netlink attribute to a message buffer
 * @msg: message buffer to add attribute to
 * @attrtype: attribute type
 * @value: numeric value
 */
static inline int nla_put_u64(struct msg_buff *msg, int attrtype, __u64 value)
{
	return nla_put(msg, attrtype, sizeof(__u64), &value);
}

/**
 * nla_put_string - Add a string netlink attribute to a message buffer
 * @msg: message buffer to add attribute to
 * @attrtype: attribute type
 * @str: NUL terminated string
 */
static inline int nla_put_string(struct msg_buff *msg, int attrtype,
				 const char *str)
{
	return nla_put(msg, attrtype, strlen(str) + 1, str);
}

/**
 * nla_put_flag - Add a flag netlink attribute to a message buffer
 * @msg: message buffer to add attribute to
 * @attrtype: attribute type
 */
static inline int nla_put_flag(struct msg_buff *msg, int attrtype)
{
	return nla_put(msg, attrtype, 0, NULL);
}

#define NLA_PUT(msg, attrtype, attrlen, data) \
	do { \
		if (unlikely(nla_put(msg, attrtype, attrlen, data) < 0)) \
			goto nla_put_failure; \
	} while(0)

#define NLA_PUT_TYPE(msg, type, attrtype, value) \
	do { \
		type __tmp = value; \
		NLA_PUT(msg, attrtype, sizeof(type), &__tmp); \
	} while(0)

#define NLA_PUT_U8(msg, attrtype, value) \
	NLA_PUT_TYPE(msg, __u8, attrtype, value)

#define NLA_PUT_U16(msg, attrtype, value) \
	NLA_PUT_TYPE(msg, __u16, attrtype, value)

#define NLA_PUT_LE16(msg, attrtype, value) \
	NLA_PUT_TYPE(msg, __le16, attrtype, value)

#define NLA_PUT_BE16(msg, attrtype, value) \
	NLA_PUT_TYPE(msg, __be16, attrtype, value)

#define NLA_PUT_U32(msg, attrtype, value) \
	NLA_PUT_TYPE(msg, __u32, attrtype, value)

#define NLA_PUT_BE32(msg, attrtype, value) \
	NLA_PUT_TYPE(msg, __be32, attrtype, value)

#define NLA_PUT_U64(msg, attrtype, value) \
	NLA_PUT_TYPE(msg, __u64, attrtype, value)

#define NLA_PUT_BE64(msg, attrtype, value) \
	NLA_PUT_TYPE(msg, __be64, attrtype, value)

#define NLA_PUT_STRING(msg, attrtype, value) \
	NLA_PUT(msg, attrtype, strlen(value) + 1, value)

#define NLA_PUT_FLAG(msg, attrtype) \
	NLA_PUT(msg, attrtype, 0, NULL)

/**
 * nla_get_u32 - return payload of u32 attribute
 * @nla: u32 netlink attribute
 */
static inline __u32 nla_get_u32(const struct nlattr *nla)
{
	return *(__u32 *) nla_data(nla);
}

/**
 * nla_get_be32 - return payload of __be32 attribute
 * @nla: __be32 netlink attribute
 */
static inline __be32 nla_get_be32(const struct nlattr *nla)
{
	return *(__be32 *) nla_data(nla);
}

/**
 * nla_get_u16 - return payload of u16 attribute
 * @nla: u16 netlink attribute
 */
static inline __u16 nla_get_u16(const struct nlattr *nla)
{
	return *(__u16 *) nla_data(nla);
}

/**
 * nla_get_be16 - return payload of __be16 attribute
 * @nla: __be16 netlink attribute
 */
static inline __be16 nla_get_be16(const struct nlattr *nla)
{
	return *(__be16 *) nla_data(nla);
}

/**
 * nla_get_le16 - return payload of __le16 attribute
 * @nla: __le16 netlink attribute
 */
static inline __le16 nla_get_le16(const struct nlattr *nla)
{
	return *(__le16 *) nla_data(nla);
}

/**
 * nla_get_u8 - return payload of u8 attribute
 * @nla: u8 netlink attribute
 */
static inline __u8 nla_get_u8(const struct nlattr *nla)
{
	return *(__u8 *) nla_data(nla);
}

/**
 * nla_get_u64 - return payload of u64 attribute
 * @nla: u64 netlink attribute
 */
static inline __u64 nla_get_u64(const struct nlattr *nla)
{
	__u64 tmp;

	nla_memcpy(&tmp, nla, sizeof(tmp));

	return tmp;
}

/**
 * nla_get_be64 - return payload of __be64 attribute
 * @nla: __be64 netlink attribute
 */
static inline __be64 nla_get_be64(const struct nlattr *nla)
{
	return *(__be64 *) nla_data(nla);
}

/**
 * nla_get_flag - return payload of flag attribute
 * @nla: flag netlink attribute
 */
static inline int nla_get_flag(const struct nlattr *nla)
{
	return !!nla;
}

/**
 * nla_nest_start - Start a new level of nested attributes
 * @msg: message buffer to add attributes to
 * @attrtype: attribute type of container
 *
 * Returns the container attribute
 */
static inline struct nlattr *nla_nest_start(struct msg_buff *msg, int attrtype)
{
	struct nlattr *start = (struct nlattr *)msg->tail;

	if (nla_put(msg, attrtype, 0, NULL) < 0)
		return NULL;

	return start;
}

/**
 * nla_nest_end - Finalize nesting of attributes
 * @msg: message buffer the attributes are stored in
 * @start: container attribute
 *
 * Corrects the container attribute header to include the all
 * appeneded attributes.
 *
 * Returns the total data length of the msg.
 */
static inline int nla_nest_end(struct msg_buff *msg, struct nlattr *start)
{
	start->nla_len = msg->tail - (unsigned char *)start;
	return msg->tail - msg->data;
}

/**
 * nla_validate_nested - Validate a stream of nested attributes
 * @start: container attribute
 * @maxtype: maximum attribute type to be expected
 * @policy: validation policy
 *
 * Validates all attributes in the nested attribute stream against the
 * specified policy. Attributes with a type exceeding maxtype will be
 * ignored. See documenation of struct nla_policy for more details.
 *
 * Returns 0 on success or a negative error code.
 */
static inline int nla_validate_nested(struct nlattr *start, int maxtype,
				      const struct nla_policy *policy)
{
	return nla_validate(nla_data(start), nla_len(start), maxtype, policy);
}

/**
 * nla_for_each_attr - iterate over a stream of attributes
 * @pos: loop counter, set to current attribute
 * @head: head of attribute stream
 * @len: length of attribute stream
 * @rem: initialized to len, holds bytes currently remaining in stream
 */
#define nla_for_each_attr(pos, head, len, rem) \
	for (pos = head, rem = len; \
	     nla_ok(pos, rem); \
	     pos = nla_next(pos, &(rem)))

/**
 * nla_for_each_nested - iterate over nested attributes
 * @pos: loop counter, set to current attribute
 * @nla: attribute containing the nested attributes
 * @rem: initialized to len, holds bytes currently remaining in stream
 */
#define nla_for_each_nested(pos, nla, rem) \
	nla_for_each_attr(pos, nla_data(nla), nla_len(nla), rem)


/**
 * struct genl_multicast_group - generic netlink multicast group
 * @name: name of the multicast group, names are per-family
 * @id: multicast group ID, assigned by the core, to use with
 *      genlmsg_multicast().
 */
struct genl_multicast_group
{
	char			name[GENL_NAMSIZ];
	__u32			id;
};

/**
 * struct genl_family - generic netlink family
 * @id: protocol family idenfitier
 * @hdrsize: length of user specific header in bytes
 * @name: name of family
 * @version: protocol version
 * @maxattr: maximum number of attributes supported
 * @attrbuf: buffer to store parsed attributes
 * @ops_list: list of all assigned operations
 * @mcast_groups: multicast groups list
 */
struct genl_family
{
	unsigned int		id;
	unsigned int		hdrsize;
	char			name[GENL_NAMSIZ];
	unsigned int		version;
	unsigned int		maxattr;
	/* 32 should be enough for most genl families */
	struct genl_multicast_group mc_groups[32];
	__u32			nl_groups;
};

/**
 * struct genl_info - receiving information
 * @snd_seq: sending sequence number
 * @nlhdr: netlink message header
 * @genlhdr: generic netlink message header
 * @userhdr: user specific header
 * @attrs: netlink attributes
 */
struct genl_info
{
	__u32			seq;
	struct nlmsghdr *	nlhdr;
	struct genlmsghdr *	genlhdr;
	void *			userhdr;
	struct nlattr **	attrs;
};

/**
 * genlmsg_put - Add generic netlink header to netlink message
 * @msg: message buffer holding the message
 * @family: generic netlink family
 * @flags netlink message flags
 * @cmd: generic netlink command
 *
 * Returns pointer to user specific header
 */
static inline void *genlmsg_put(struct msg_buff *msg, struct genl_family *family,
		int flags, __u8 cmd)
{
	const unsigned hdrsize = NLMSG_HDRLEN + GENL_HDRLEN + family->hdrsize;
	struct nlmsghdr *nlh;
	struct genlmsghdr *hdr;

	if (unlikely(msg_tailroom(msg) < nlmsg_total_size(hdrsize)))
		return NULL;

	nlh = msg_put(msg, hdrsize);

	nlh->nlmsg_type = family->id;
	nlh->nlmsg_flags = flags;
	/* pid and seq will be reassigned in genl_send() */
	nlh->nlmsg_pid = 0;
	nlh->nlmsg_seq = 0;

	hdr = nlmsg_data(nlh);
	hdr->cmd = cmd;
	hdr->version = family->version; /* truncated to u8! */
	hdr->reserved = 0;

	return (char *) hdr + GENL_HDRLEN;
}

/**
 * gennlmsg_data - head of message payload
 * @gnlh: genetlink messsage header
 */
static inline void *genlmsg_data(const struct genlmsghdr *gnlh)
{
	return ((unsigned char *) gnlh + GENL_HDRLEN);
}

/**
 * genlmsg_len - length of message payload
 * @gnlh: genetlink message header
 */
static inline int genlmsg_len(const struct genlmsghdr *gnlh)
{
	struct nlmsghdr *nlh = (struct nlmsghdr *)((unsigned char *)gnlh -
							NLMSG_HDRLEN);
	return (nlh->nlmsg_len - GENL_HDRLEN - NLMSG_HDRLEN);
}

/**
 * genlmsg_msg_size - length of genetlink message not including padding
 * @payload: length of message payload
 */
static inline int genlmsg_msg_size(int payload)
{
	return GENL_HDRLEN + payload;
}

/**
 * genlmsg_total_size - length of genetlink message including padding
 * @payload: length of message payload
 */
static inline int genlmsg_total_size(int payload)
{
	return NLMSG_ALIGN(genlmsg_msg_size(payload));
}

/*
 * Some helpers to simplify communicating with a particular family
 */
struct genl_sock {
	struct sockaddr_nl	s_local;
	struct sockaddr_nl	s_peer;
	int			s_fd;
	unsigned int		s_seq_next;
	unsigned int		s_seq_expect;
	unsigned int		s_flags;
	struct genl_family	*s_family;
};

extern struct genl_sock *genl_connect_to_family(struct genl_family *family);
extern int genl_join_mc_group(struct genl_sock *s, const char *name);
extern int genl_send(struct genl_sock *s, struct msg_buff *msg);
enum {
	E_RCV_TIMEDOUT = 0,
	E_RCV_FAILED,
	E_RCV_NO_SOURCE_ADDR,
	E_RCV_SEQ_MISMATCH,
	E_RCV_MSG_TRUNC,
	E_RCV_UNEXPECTED_TYPE,
	E_RCV_NLMSG_DONE,
	E_RCV_ERROR_REPLY,
};
/* returns negative E_RCV_*, or length of message */
extern int genl_recv_msgs(struct genl_sock *s, struct iovec *iov, char **err_desc, int timeout_ms);


#endif	/* LIBGENL_H */
