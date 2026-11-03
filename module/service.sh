#!/system/bin/sh
PATH=/data/adb/ksu/bin:$PATH
MODDIR=${0%/*}
KO="$MODDIR/ko/fgetpriority.ko"

if lsmod | grep -q fgetpriority; then
	rmmod "$KO"
fi

if ! insmod "$KO" ; then
	ksud insmod "$KO"
fi
