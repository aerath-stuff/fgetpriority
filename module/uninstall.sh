#!/system/bin/sh
PATH=/data/adb/ksu/bin:$PATH

if [ "$KSU_LATE_LOAD" = "1" ]; then
	(lsmod | grep -q fgetpriority && rmmod fgetpriority ) > /dev/null 2>1 &
fi

# EOF
