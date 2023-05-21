#!/bin/sh

cd PISE-MAAT
python3 -m $1 &
cd ../
sleep 4

cd PISEClient
mvn -q exec:java -Dexec.mainClass="com.pise.client.PiseLearner"
