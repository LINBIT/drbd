#include <linux/cpumask.h>

int main(void)
{
	int e = cpumask_empty((struct cpumask *)NULL);

	return e;
}
