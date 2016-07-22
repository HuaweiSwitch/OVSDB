#!/bin/sh

# Package all
mkdir ovsdb_dir
cp utilities/ovs-pki                          ovsdb_dir/
cp utilities/ovs-vsctl                        ovsdb_dir/
cp ovsdb/ovsdb-client                         ovsdb_dir/
cp ovsdb/ovsdb-server                         ovsdb_dir/
cp ovsdb/ovsdb-tool                           ovsdb_dir/
cp vtep/vtep-ctl                              ovsdb_dir/
cp vtep/vtep.ovsschema                        ovsdb_dir/
cp ./netconf_depend_so/libnetconf.so.0        ovsdb_dir/
#cp ./netconf_depend_so/libcurl.so.4           ovsdb_dir/
cp ./netconf_depend_so/libssh.so.4            ovsdb_dir/
cp ./netconf_depend_so/libssh_threads.so.4    ovsdb_dir/
cp ovsdb-client.cfg                           ovsdb_dir/
cp ovsdb-init                                 ovsdb_dir/

# Make the base directory
cd ovsdb_dir
mkdir ./mydeb
mkdir -p ./mydeb/DEBIAN
touch ./mydeb/DEBIAN/control
touch ./mydeb/DEBIAN/postinst
touch ./mydeb/DEBIAN/postrm

# Change the file's authority
chmod 775 ./mydeb/DEBIAN/postinst
chmod 775 ./mydeb/DEBIAN/postrm
chmod 775 ./mydeb/DEBIAN/control

# Make the lib&bin directory
mkdir -p ./mydeb/etc
mkdir -p ./mydeb/etc/openvswitch
mkdir -p ./mydeb/usr/local/etc/openvswitch/
mkdir -p ./mydeb/usr/local/var/run/
mkdir -p ./mydeb/usr/local/var/run/openvswitch/
mkdir -p ./mydeb/usr/bin
mkdir -p ./mydeb/usr/lib/powerpc-linux-gnu

# Copy files
cp vtep.ovsschema ./mydeb/etc
cp ovs-pki ./mydeb/usr/bin
cp ovs-vsctl ./mydeb/usr/bin
cp ovsdb-client ./mydeb/usr/bin
cp ovsdb-server ./mydeb/usr/bin
cp ovsdb-tool ./mydeb/usr/bin
cp vtep-ctl ./mydeb/usr/bin
cp libnetconf.so.0 ./mydeb/usr/lib/powerpc-linux-gnu
#cp libcurl.so.4 ./mydeb/usr/lib/powerpc-linux-gnu
cp libssh.so.4 ./mydeb/usr/lib/powerpc-linux-gnu
cp libssh_threads.so.4 ./mydeb/usr/lib/powerpc-linux-gnu
cp ovsdb-client.cfg ./mydeb/etc/openvswitch
cp ovsdb-init ./mydeb/etc/openvswitch

# Write files
echo Package: ovsdb >> ./mydeb/DEBIAN/control
echo Version: 2.5.0 >> ./mydeb/DEBIAN/control
echo Section: utils >> ./mydeb/DEBIAN/control
echo Priority: optional >> ./mydeb/DEBIAN/control
echo Architecture: powerpc >> ./mydeb/DEBIAN/control
echo Maintainer: huawei >> ./mydeb/DEBIAN/control
echo Description: ovsdb 2.5.0 >> ./mydeb/DEBIAN/control

echo '#!/bin/bash' >> ./mydeb/DEBIAN/postinst
echo 'touch /var/log/openflow_install.log' >> ./mydeb/DEBIAN/postinst
echo '#!/bin/bash' >> ./mydeb/DEBIAN/postrm
echo 'rm -rf /var/log/openflow_install.log' >> ./mydeb/DEBIAN/postrm
echo 'rm -rf /etc/vtep.ovsschema' >> ./mydeb/DEBIAN/postrm
echo 'rm -rf /usr/bin/ovs-pki' >> ./mydeb/DEBIAN/postrm
echo 'rm -rf /usr/bin/ovs-vsctl' >> ./mydeb/DEBIAN/postrm
echo 'rm -rf /usr/bin/ovsdb-client' >> ./mydeb/DEBIAN/postrm
echo 'rm -rf /usr/bin/ovsdb-server' >> ./mydeb/DEBIAN/postrm
echo 'rm -rf /usr/bin/ovsdb-tool' >> ./mydeb/DEBIAN/postrm
echo 'rm -rf /usr/bin/vtep-ctl' >> ./mydeb/DEBIAN/postrm
echo 'rm -rf /etc/init.d/ovsdb-init' >> ./mydeb/DEBIAN/postrm
#echo 'rm -rf /usr/lib/powerpc-linux-gnu/libnetconf.so.0' >> ./mydeb/DEBIAN/postrm
#echo 'rm -rf /etc/openvswitch/ovsdb-client.cfg' >> ./mydeb/DEBIAN/postrm

# Make the dpkg file
PACKAGE_NAME=ovsdb-2.5.0.deb
dpkg -b mydeb ${PACKAGE_NAME}

mv ${PACKAGE_NAME} ./../
rm -rf mydeb
cd ..
rm -rf ovsdb_dir
chmod 777 ${PACKAGE_NAME}
echo "************************************************************************************************************"
echo "* Finish building openflow package: ${PACKAGE_NAME} (Install it with command \"dpkg -i ${PACKAGE_NAME}\"). *"
echo "************************************************************************************************************"
