#!/bin/bash -e

if [ "$1" = "-t" ]; then
    shift
    fstype=$1
    shift
fi

if [ -z "$fstype" ]; then
    fstype="ext4"
fi

MKFS=`which mkfs.$fstype 2> /dev/null` || echo -n ""
if [ -z ${MKFS} ]; then
    echo "test skip: mkfs.$fstype"
    exit 0
fi

file=`mktemp`
dd if=/dev/zero of=$file bs=1024 count=20480

yes | mkfs.$fstype $file >/dev/null

${VALGRIND_CMD} ./boot -d $file -t $fstype $@

rm $file
