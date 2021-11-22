/*
  Before Linux upstream commit aeb193ea6cef28e33589de05ef932424f8e19bde
  (which landed with Linux 3.11)
  callers of skb_seq_read() are forced to call skb_abort_seq_read()
  even when consuming all the data because the last call to
  skb_seq_read (the one that returns 0 to indicate the end) fails to
  unmap the last fragment page.

  I is not possible to test for the kernel-bug via the kernel-headers,
  so assume all kernels before 3.11 to contain the bug.
*/

#include <linux/version.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,11,0)
# error Don't need skb_abort_seq_read()
#endif
