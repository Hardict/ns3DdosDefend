#!/bin/bash
# 
# for i in {1..5}
# do
#   ./waf -v --run "scratch/rgg2 --nAdHocNum=60 --nNs3Seed=6 --nSrandSeed=${i} --nOutFileId=${i} --kProbContinue=0.15 --kProbNew=0.15 --kPacketMaxSpeed=50"
# done

./rgg2_1.sh 0 40 1 1 1 energy kUpdateTime1_keypoint &
sleep 5s

./rgg2_1.sh 0 40 1 1 2 energy kUpdateTime2_keypoint &
sleep 5s

echo "final"