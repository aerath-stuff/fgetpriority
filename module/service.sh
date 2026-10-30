#!/system/bin/sh
PATH=/data/adb/ksu/bin:$PATH
MODDIR=${0%/*}
KO="$MODDIR/ko/fgetpriority.ko"

kptr_set=$(cat /proc/sys/kernel/kptr_restrict)
echo 1 > /proc/sys/kernel/kptr_restrict
addr=$(grep " kallsyms_lookup_name$" /proc/kallsyms | awk {'print "0x"$1'})
echo $kptr_set > /proc/sys/kernel/kptr_restrict

if lsmod | grep -q fgetpriority; then
	rmmod "$KO"
fi

if ! insmod "$KO" kallsyms_lookup_name_fn="$addr" ; then
	ksud insmod "$KO" kallsyms_lookup_name_fn="$addr"
fi
