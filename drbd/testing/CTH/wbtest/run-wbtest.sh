#!/bin/sh

# device name for drive that holds safe directory
drv_safe="/dev/hdX"
drv_test="/dev/hdY"

# path prefixes for safe and test directories
safe_dir="/path/on/drv_safe/wbtest-safe"
test_dir="/path/on/drv_test/wbtest-test"

# path prefix to wbtest and run-wbtest.sh
wbtest_path="/root"

if [ ! -d $safe_dir ]; then
    mkdir -p $safe_dir
fi

if [ ! -d $test_dir ]; then
    mkdir -p $test_dir
	
fi

# make sure that the safe drive has write cache disabled
hdparm -W0 $drv_safe
# make sure that the test drive has write cache enabled
hdparm -W1 $drv_test

RC_LOCAL_TOUCHED=/var/wbtest-mod-rc-local

if [ ! -f $RC_LOCAL_TOUCHED ]; then
    echo "${wbtest_path}/run-wbtest.sh" >> /etc/rc.d/rc.local
    > $RC_LOCAL_TOUCHED
fi

# Run it!
${wbtest_path}/wbtest -p 0 -c 40 -s $safe_dir -t $test_dir &
