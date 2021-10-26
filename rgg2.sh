#!/bin/bash
for i in {1..5}
do
  ./waf -v --run "scratch/rgg2 --nAdHocNum=60 --nNs3Seed=6 --nSrandSeed=${i} --nOutFileId=${i} --kProbContinue=0.1 --kProbNew=0.1 --kPacketMaxSpeed=50"
done