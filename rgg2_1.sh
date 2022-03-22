#!/bin/bash
# 
# for i in {1..5}
# do
#   ./waf -v --run "scratch/rgg2 --nAdHocNum=60 --nNs3Seed=6 --nSrandSeed=${i} --nOutFileId=${i} --kProbContinue=0.15 --kProbNew=0.15 --kPacketMaxSpeed=50"
# done

for ((i = $1; i<=$2; i++))
do
  prob1=`expr ${i} \* 4`
  prob2=50
  # prob=${i}
  echo "experiment[${i}], p1: ${prob1}, p2: ${prob2}, $4"
  ./waf -v --run "scratch/rgg2 --nAdHocNum=80 --nNs3Seed=$3 --nSrandSeed=$3 --nOutFileId=$4 --kProbProbeContinue=${prob1} --kProbDefendContinue=${prob2}
                  --kProbeTtl=2 --kDefendTtl=3 --kPacketSize=1024 --kServerRate=20 --kAttackerRate=80" &> ./mylog/energy_p1_1_$4_${i}.txt
done
