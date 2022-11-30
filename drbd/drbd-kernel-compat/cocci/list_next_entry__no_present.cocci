@@
identifier pos, member;
@@
- list_next_entry(pos, member)
+ list_entry((pos)->member.next, typeof(*(pos)), member)
