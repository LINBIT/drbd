# These two gdb user defined commands might help you to unterstand
# kernel lockups. 
# Use these functions on a GDB running User Mode Linux in SKAS mode.
#
# You can load this file into GDB by using the 'source' command,
# or simply put it into your .gdbinit
#
# -Philipp


define linux-bt
  set $bt_switch_buf = ((struct task_struct*)$arg0)->thread.mode.skas.switch_buf
  set $bt_ebp = ((unsigned long*)$bt_switch_buf)[3]
  set $bt_i = 0
  printf "-#-  ---EBP----  ---EIP----    ---------FUNCTION---------\n"
  while $bt_i < 32
    set $bt_eip = ((unsigned long*)$bt_ebp)[1]
    if $bt_eip == __restore
      set $bt_i = 32
    else 
      printf "#%-2d  0x%8x  0x%8x in ", $bt_i, $bt_ebp, $bt_eip
      info symbol $bt_eip
      set $bt_ebp = ((unsigned long*)$bt_ebp)[0]
      set $bt_i = $bt_i + 1
    end
  end
end

document linux-bt
  linux-bt takes the address of a task_struct as argument,
  and prints the stack back trace of that task.
  You might use linux-ps to find the addresses of all available
  tasks on the system
end

define linux-ps
  set $ps_i=0
  printf "---TASK---  -PID-  --------COMM----------\n"
  while $ps_i < 1024
    set $ps_p = pidhash[$ps_i]
      while $ps_p
        printf "0x%8x  %-5d  %-20s\n", $ps_p, $ps_p->pid, $ps_p->comm
        set $ps_p = $ps_p->pidhash_next
      end
    set $ps_i = $ps_i + 1
  end
end

document linux-ps
  linux-ps lists all tasks on the system. 
  Also have a look at linux-bt.
end
