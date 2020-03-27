/* {"version": "4.19", "commit": "d34ac5cd3a73aacd11009c4fc3ba15d7ea62c411", "comment": "RDMA, core and ULPs: Declare ib_post_send() and ib_post_recv() arguments const", "author": "Bart Van Assche <bart.vanassche@wdc.com>", "date": "Wed Jul 18 09:25:32 2018 -0700" } */
#include <rdma/ib_verbs.h>

#ifndef __same_type
# define __same_type(a, b) __builtin_types_compatible_p(typeof(a), typeof(b))
#endif

int ib_post_send_before_4_19(struct ib_qp *qp,
			     struct ib_send_wr *send_wr,
			     struct ib_send_wr **bad_send_wr);

int ib_post_send_after_4_19(struct ib_qp *qp,
			    const struct ib_send_wr *send_wr,
			    const struct ib_send_wr **bad_send_wr);

int foo(void)
{
	struct ib_qp *qp;
	const struct ib_send_wr *send_wr;
	const struct ib_send_wr **bad_send_wr;

        BUILD_BUG_ON(!(__same_type(ib_post_send_after_4_19, ib_post_send)));
        return ib_post_send(qp, send_wr, bad_send_wr);
}
