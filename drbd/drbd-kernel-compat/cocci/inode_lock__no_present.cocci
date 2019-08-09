@@
expression ino;
@@
(
- inode_lock(ino)
+ mutex_lock(&ino->i_mutex)
|
- inode_unlock(ino)
+ mutex_unlock(&ino->i_mutex)
)
