#include <stdio.h>
#include <linux/drbd.h>

#define SZO(x) \
({ int _i = sizeof(x); printf("sizeof(" #x ") = %d\n", _i); \
 if( _i % 8 ) printf(" WARN sizeof(" #x ") %% 8 != 0\n"); _i; })

#define DRBD_08_SUM 1176

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

	printf("sum = %d  DRBD_08_SUM = %d\n",sum,DRBD_08_SUM);

	printf(sum == DRBD_08_SUM ? "OKAY\n" : "FAILED\n" );

	return sum != DRBD_08_SUM; /* if not equal, exit code is non-zero */
}
