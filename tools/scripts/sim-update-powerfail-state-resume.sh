#!/bin/bash
V=`./wolfboot.elf update_trigger get_version 2>/dev/null`
if [ "x$V" != "x1" ]; then
    echo "Failed first boot with update_trigger"
    exit 1
fi

# powerfail_state <state-slot> <trigger-count>
./wolfboot.elf powerfail_state 0 3 get_version 2>/dev/null
./wolfboot.elf powerfail_state 0 3 get_version 2>/dev/null

for i in {1..30}
do
    ./wolfboot.elf powerfail_state 0 4 get_version 2>/dev/null
done

V=`./wolfboot.elf get_version 2>/dev/null`
if [ "x$V" != "x2" ]; then
    echo "Failed update (V: $V)"
    exit 1
fi

./wolfboot.elf powerfail_state 1 2 get_version 2>/dev/null
./wolfboot.elf powerfail_state 1 2 get_version 2>/dev/null

for i in {1..30}
do
    ./wolfboot.elf powerfail_state 1 3 get_version 2>/dev/null
done

V=`./wolfboot.elf get_version 2>/dev/null`
if [ "x$V" != "x1" ]; then
    echo "Failed fallback (V: $V)"
    exit 1
fi

echo Test successful.
exit 0
