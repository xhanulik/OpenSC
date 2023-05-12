#!/bin/bash

set -ex -o xtrace

# install the opensc
sudo make install
export LD_LIBRARY_PATH=/usr/local/lib

# setup java stuff and virtal smartcard
. .github/setup-java.sh

# The OpenFIPS201 Applet
if [ ! -d "OpenFIPS201" ]; then
	git clone --recursive https://github.com/makinako/OpenFIPS201.git
fi
pushd OpenFIPS201
ant all -f build/build.xml
popd

echo "com.licel.jcardsim.card.applet.0.AID=A000000308000010000100" > openfips201_jcardsim.cfg;
echo "com.licel.jcardsim.card.applet.0.Class=com.makina.security.openfips201.OpenFIPS201" >> openfips201_jcardsim.cfg;
echo "com.licel.jcardsim.card.ATR=3B80800101" >> openfips201_jcardsim.cfg;
echo "com.licel.jcardsim.vsmartcard.host=localhost" >> openfips201_jcardsim.cfg;
echo "com.licel.jcardsim.vsmartcard.port=35963" >> openfips201_jcardsim.cfg;

# prepare pcscd
. .github/restart-pcscd.sh

# start the applet and run couple of commands against that
java -noverify -cp OpenFIPS201/build/bin/:jcardsim/target/jcardsim-3.0.5-SNAPSHOT.jar com.licel.jcardsim.remote.VSmartCard openfips201_jcardsim.cfg >/dev/null &
PID=$!
sleep 5
opensc-tool --card-driver default --send-apdu 80b80000120ba000000308000010000100050000020F0F
