#!/bin/sh

if ! [ -d Tests/kaas ]; then
	echo "Tests/kaas not found. Run this from repo root"
fi

cd Tests/kaas

virtualenv .venv
. .venv/bin/activate
pip install -r requirements.txt

BATCH1="noris-1.34 scaleup-1.34 syself-1.34 teuto-1.34"
BATCH2="noris-1.35 scaleup-1.35 syself-1.35 teuto-1.35"
BATCH3="noris-1.36 scaleup-1.36 syself-1.36 teuto-1.36"

./k8s_test.py provision $BATCH1
./k8s_test.py run $BATCH1
./k8s_test.py unprovision $BATCH1

./k8s_test.py provision $BATCH2
./k8s_test.py run $BATCH2
./k8s_test.py unprovision $BATCH2

./k8s_test.py provision $BATCH3
./k8s_test.py run $BATCH3
./k8s_test.py unprovision $BATCH3

./k8s_test.py aggregate noris-kaas noris-1.34 noris-1.35 noris-1.36
./k8s_test.py aggregate scaleup-kaas scaleup-1.34 scaleup-1.35 scaleup-1.36
./k8s_test.py aggregate syself-kaas syself-1.34 syself-1.35 syself-1.36
./k8s_test.py aggregate teuto teuto-1.34 teuto-1.35 teuto-1.36
