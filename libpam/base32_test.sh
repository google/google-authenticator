#!/bin/bash

a=0
while [ $a -lt 150 ] ;do
	dd if=/dev/urandom bs=$RANDOM count=1 of=testfile > /dev/null 2>&1
	cat testfile | ./base32 -e | ./base32 -d > testfile.out
	if ! cmp -s testfile testfile.out ; then
		echo FAILED
		exit 1
	fi
	a=$((a + 1))
done

rm testfile testfile.out
