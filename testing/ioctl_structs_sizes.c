#include <stdio.h>
#include <linux/drbd.h>

#define SZO(x) \
({ int _i = sizeof(x); printf("sizeof(" #x ") = %d\n", _i); _i; })


#define DRBD_07_SUM 1140

int main()
{
	int sum=0;

	sum += SZO(struct disk_config);
	sum += SZO(struct net_config);
	sum += SZO(struct syncer_config);
	sum += SZO(struct ioctl_disk_config);
	sum += SZO(struct ioctl_net_config);
	sum += SZO(struct ioctl_syncer_config);
	sum += SZO(struct ioctl_wait);
	sum += SZO(struct ioctl_get_config);

	printf("sum = %d  DRBD_07_SUM = %d\n",sum,DRBD_07_SUM);

	printf(sum == DRBD_07_SUM ? "OKAY\n" : "FAILED\n" );

	return sum != DRBD_07_SUM; /* if not equal, exit code is non-zero */
}
