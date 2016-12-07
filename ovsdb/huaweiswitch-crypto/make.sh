#!/bin/bash

gcc huaweiswitch-crypto.c -g3 -shared -o libhwscrypto.so -lcrypto
mkdir ../netconf_depend_so/
cp libhwscrypto.so ../netconf_depend_so/
cp libhwscrypto.so /usr/local/lib/
gcc huaweiswitch-keygen.c -g3 -o huaweiswitch-keygen -lcrypto -lhwscrypto
gcc huaweiswitch-key.c -g3 -o huaweiswitch-key -lcrypto -lhwscrypto

