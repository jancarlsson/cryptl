#!/bin/bash

case $# in
    1) SIGN_INPUT=$1 ;;
    0) echo "usage: "$0" sign.input"
       exit
esac

FAIL_COUNT=0
TMP_FILE=ED25519_test.tmp

for LINE in `cat $SIGN_INPUT`
do
    SKPK=`echo $LINE | awk -F: '{print $1}'`
    PK=`echo $LINE | awk -F: '{print $2}'`
    MSG=`echo $LINE | awk -F: '{print $3}'`
    RSMSG=`echo $LINE | awk -F: '{print $4}'`

    SK=`echo $SKPK | cut -c 1-64`

    TEST_FAILED=

    # check public key
    PK_TEST=`./ED25519_test -s $SK | awk '{print $2}'`
    if [ $PK_TEST != $PK ]
    then
	echo "bad public key for "$SK
	TEST_FAILED=1
    fi

    # sign message
    if [ $MSG ]
    then
	./ED25519_test -s $SK -m $MSG > $TMP_FILE
    else
	./ED25519_test -s $SK -m "" > $TMP_FILE
    fi
    R=`head -1 $TMP_FILE | awk '{print $2}'`
    S=`tail -1 $TMP_FILE | awk '{print $2}'`

    # check signature
    RSMSG_TEST=$R$S$MSG
    if [ $RSMSG_TEST != $RSMSG ]
    then
	echo "bad signature for "$SK
	TEST_FAILED=1
    fi

    # open message (verify signature)
    if [ $MSG ]
    then
	STATUS=`./ED25519_test -p $PK -m $MSG -R $R -S $S`
    else
	STATUS=`./ED25519_test -p $PK -m "" -R $R -S $S`
    fi
    echo $STATUS" "$SK
    if [ $STATUS != "OK" ]
    then
	TEST_FAILED=1
    fi

    if [ $TEST_FAILED ]
    then
	FAIL_COUNT=`expr $FAIL_COUNT + 1`
    fi

done

if [ $FAIL_COUNT == 0 ]
then
    echo All tests passed
else
    echo "There were "$FAIL_COUNT" failures"
fi

rm $TMP_FILE
