#!/bin/bash
LOOP=10000

if [ "$1" = "" ]; then
    echo "Usage: $0 <nic>"
    exit
fi
if [ "$2" != "" ]; then
    LOOP=$2
fi
NIC=$1
T1=`ifconfig $NIC | grep "RX packets" | awk '{print $5}' `
R1=`ifconfig $NIC | grep "TX packets" | awk '{print $5}' `
for i in `seq 1 $LOOP`; do
    sleep 1
    T2=`ifconfig $NIC | grep "RX packets" | awk '{print $5}' `
    R2=`ifconfig $NIC | grep "TX packets" | awk '{print $5}' `
    TX=$(expr $T2 - $T1 )
    RX=$(expr $R2 - $R1 )
    echo "TX=$TX    RX=$RX"
    printf "RX=%d Mps\n" $(( ($R2 - $R1)*8/1024000/$TIME ))
    T1=$T2
    R1=$R2
done
