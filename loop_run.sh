#!/bin/sh
if [ "$#" != "2" ]; then
	echo "Usage: $0 <prg> 'args ... ' "
    exit
fi
PRG=$1
ARGS=$2

while true; do
    echo "Run: $PRG $ARGS"
    logger "Run: $PRG $ARGS"
	$PRG $ARGS
    sleep 1
done

