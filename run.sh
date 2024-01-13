#!/bin/sh

cd PISE-MAAT/pise
mkdir -p tmp
mount -t tmpfs -o size=1000m -o 'context="system_u:object_r:tmp_t:s0:c127,c456",noexec' PISE_serialization_tmpfs ./tmp
chmod 777 ./tmp
cd tmp
rm -rf ./*
mkdir -p init_state probing
cd ../..
rm -f ./pise/tmp/init_state/* ./pise/tmp/probing/*
./venv/bin/python -m $1 &
cd ../
sleep 20

cd PISEClient
mvn -q exec:java -Dexec.mainClass="com.pise.client.PiseLearner"

cd ../PISE-MAAT/pise
rm -rf ./tmp/*
sudo umount tmp
rmdir tmp
