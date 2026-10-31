#!/bin/sh

if ! [ -d Tests/iaas ]; then
	echo "Tests/iaas not found. Run this from repo root"
fi

cd Tests/iaas

virtualenv .venv
. .venv/bin/activate
pip install -r requirements.txt

BATCH="\
scs2 \
artcodix-muc artcodix-ro \
cah-dd8a \
pco-prod1 pco-prod2 pco-prod3 pco-prod4 \
regio-a \
scaleup-occ2 scaleup-occ3 \
syseleven-dus2 syseleven-ham1 \
"
# currently not reachable from outside: "cc-rrze",

./openstack_test.py cleanup $BATCH

./openstack_test.py run $BATCH

# TODO make this more efficient (each call is two roundtrips to the server)
./openstack_test.py aggregate scs2
./openstack_test.py aggregate artcodix artcodix-muc artcodix-ro
./openstack_test.py aggregate cah-dd8a
./openstack_test.py aggregate pco-prod pco-prod1 pco-prod2 pco-prod3 pco-prod4
./openstack_test.py aggregate regio-a
./openstack_test.py aggregate scaleup-occ2 scaleup-occ3
./openstack_test.py aggregate syseleven syseleven-dus2 syseleven-ham1
