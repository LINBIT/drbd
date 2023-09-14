#ifndef OVERFLOW_H
#define OVERFLOW_H

/* RHEL7 has a gcc-4.x which lacks __builtin_add_overflow() */
#if __GNUC__ < 5
#define check_add_overflow(a, b, d)  ({ *(d) = (a) + (b); *(d) < (a); })
#endif

#endif /* OVERFLOW_H */
