#!/bin/bash

case $# in
    1) DIR=$1 ;;
    0) echo "usage: "$0" path_to_directory_with_test_files"
       exit
esac

LOG_FILE=AESAVS.tmp
cp /dev/null $LOG_FILE

for BITS in 128 192 256
do
    for MODE in ECB CBC OFB
    do
	for KAT in GFSbox KeySbox VarKey VarTxt
	do
	    echo | tee -a $LOG_FILE
	    echo $MODE$KAT$BITS".rsp" | tee -a $LOG_FILE
	    cat $DIR"/"$MODE$KAT$BITS".rsp" \
		| ./AESAVS -b $BITS -m $MODE \
		| tee -a $LOG_FILE
	done
    done
done

for BITS in 128 192 256
do
    for MODE in CFB
    do
	for KAT in GFSbox KeySbox VarKey VarTxt
	do
	    echo | tee -a $LOG_FILE
	    echo $MODE"128"$KAT$BITS".rsp" | tee -a $LOG_FILE
	    cat $DIR"/"$MODE"128"$KAT$BITS".rsp" \
		| ./AESAVS -b $BITS -m $MODE \
		| tee -a $LOG_FILE
	done
    done
done

FAIL_COUNT=`grep -c FAIL $LOG_FILE`
echo
if [ $FAIL_COUNT == 0 ]
then
    echo All tests passed
else
    echo "There were "$FAIL_COUNT" failures"
    grep FAIL $LOG_FILE
fi
rm $LOG_FILE
