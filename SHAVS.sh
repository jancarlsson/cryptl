#!/bin/bash

case $# in
  1) DIR=$1 ;;
  0) echo "usage: "$0" path_to_directory_with_byte_test_vector_files"
     exit
esac

LOG_FILE=SHAVS.tmp
cp /dev/null $LOG_FILE

for BITS in 1 224 256 384 512
do
  echo | tee -a $LOG_FILE
  echo "SHA"$BITS" Monte Carlo" | tee -a $LOG_FILE

  cat $DIR"/SHA"$BITS"Monte.txt" \
      | ./SHAVS -b $BITS \
      | tee -a $LOG_FILE
done

for BITS in 1 224 256 384 512
do
  echo | tee -a $LOG_FILE
  echo "SHA"$BITS" short messages" | tee -a $LOG_FILE

  cat $DIR"/SHA"$BITS"ShortMsg.rsp" \
      | ./SHAVS -b $BITS \
      | tee -a $LOG_FILE
done

for BITS in 1 224 256 384 512
do
  echo | tee -a $LOG_FILE
  echo "SHA"$BITS" long messages" | tee -a $LOG_FILE

  cat $DIR"/SHA"$BITS"LongMsg.rsp" \
      | ./SHAVS -b $BITS \
      | tee -a $LOG_FILE
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
