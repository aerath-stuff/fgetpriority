### fgetpriority

A small LKM to filter sys_getpriority / sys_setpriority / sys_ioprio_get / sys_ioprio_set

Usage (if LKM):

```shell
#!/bin/sh

kptr_set=$(cat /proc/sys/kernel/kptr_restrict)
echo 1 > /proc/sys/kernel/kptr_restrict
addr=$(grep " kallsyms_lookup_name$" /proc/kallsyms | awk {'print "0x"$1'})
echo $kptr_set > /proc/sys/kernel/kptr_restrict

insmod fgetpriority.ko kallsyms_lookup_name_fn="$addr"

```
Compatibility:
- CONFIG_KALLSYMS=y
