@@
struct file *file;
@@
- file_inode(file)
+ file->f_dentry->d_inode
