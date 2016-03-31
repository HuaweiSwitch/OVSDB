#!/bin/sh

chmod 777 *

export PATH=/opt/cross_tools/sysroot-ppc_e500mc-glibc_small/x86_64-wrlinuxsdk-linux/usr/bin/powerpc-wrs-linux:$PATH
export SYSROOT=/opt/cross_tools/sysroot-ppc_e500mc-glibc_small/ppce500mc-wrs-linux
export NETCONFLIB=$PWD/wr_netconf_depend_so

./configure CC=powerpc-wrs-linux-gcc CXX=powerpc-wrs-linux-g++ LDFLAGS="-L$SYSROOT/lib -L$NETCONFLIB --sysroot=$SYSROOT -lpthread -latomic -lpthread -lnetconf -lcurl  -lidn -lnspr4 -lnss3 -lnssutil3 -lplc4 -lplds4 -lsmime3 -lssh2 -lssl3 -lxslt -lxml2 -lm" CFLAGS="-I$SYSROOT/usr/include -DHAVE_OPENSSL" --host=i686-linux

core_num=`cat /proc/cpuinfo | grep processor | wc -l`
job_num=$((core_num * 2 + 2))

make -j${job_num}

echo "*******************************************"
echo "* Final openflow package: openflow.tar.gz *"
echo "*******************************************"
