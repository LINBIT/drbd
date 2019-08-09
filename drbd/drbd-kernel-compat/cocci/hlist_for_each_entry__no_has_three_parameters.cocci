@@
iterator hlist_for_each_entry =~ "hlist_for_each_entry";
expression pos, head;
identifier memb;
@@
- hlist_for_each_entry(pos, head, memb)
+ for (pos = hlist_entry_safe((head)->first, typeof(*(pos)), memb); pos; pos = hlist_entry_safe((pos)->memb.next, typeof(*(pos)), memb))
{
...
}

@@
expression ptr, memb;
type typ;
@@
- hlist_entry_safe(ptr, typ, memb)
+ (ptr) ? hlist_entry(ptr, typ, memb) : NULL
