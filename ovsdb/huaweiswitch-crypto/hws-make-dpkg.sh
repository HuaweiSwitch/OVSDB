#!/bin/sh

# Package all
mkdir ovsdb_dir
cp libhwscrypto.so         ovsdb_dir/
cp huaweiswitch-key        ovsdb_dir/
cp huaweiswitch-keygen     ovsdb_dir/

# Make the base directory
cd ovsdb_dir
mkdir ./mydeb
mkdir -p ./mydeb/DEBIAN
touch ./mydeb/DEBIAN/control
touch ./mydeb/DEBIAN/postinst
touch ./mydeb/DEBIAN/postrm

# Change the file's authority
chmod 755 ./mydeb/DEBIAN/postinst
chmod 755 ./mydeb/DEBIAN/postrm
chmod 755 ./mydeb/DEBIAN/control

# Make the lib&bin directory
mkdir -p ./mydeb/usr/lib/powerpc-linux-gnu
mkdir -p ./mydeb/root/huaweiswitch-key

# Copy files
cp libhwscrypto.so ./mydeb/usr/lib/powerpc-linux-gnu
cp huaweiswitch-key ./mydeb/root/huaweiswitch-key
cp huaweiswitch-keygen ./mydeb/root/huaweiswitch-key

chmod 700 ./mydeb/root/huaweiswitch-key -R

# Write files
echo Package: huaweiswitch-key >> ./mydeb/DEBIAN/control
echo Version: 1.0.0 >> ./mydeb/DEBIAN/control
echo Section: utils >> ./mydeb/DEBIAN/control
echo Priority: optional >> ./mydeb/DEBIAN/control
echo Architecture: powerpc >> ./mydeb/DEBIAN/control
echo Maintainer: huawei >> ./mydeb/DEBIAN/control
echo Description: huaweiswitch-key 1.0.0 >> ./mydeb/DEBIAN/control

echo '#!/bin/bash' >> ./mydeb/DEBIAN/postinst
echo 'touch /var/log/huaweiswitch-key.log' >> ./mydeb/DEBIAN/postinst
echo '#!/bin/bash' >> ./mydeb/DEBIAN/postrm
echo 'rm -rf /var/log/huaweiswitch-key.log' >> ./mydeb/DEBIAN/postrm
echo 'rm -rf /root/huaweiswitch-key' >> ./mydeb/DEBIAN/postrm

# Make the dpkg file
PACKAGE_NAME=huaweiswitch-key.deb
dpkg -b mydeb ${PACKAGE_NAME}

mv ${PACKAGE_NAME} ./../
rm -rf mydeb
cd ..
rm -rf ovsdb_dir
chmod 777 ${PACKAGE_NAME}
echo "************************************************************************************************************"
echo "* Finish building openflow package: ${PACKAGE_NAME} (Install it with command \"dpkg -i ${PACKAGE_NAME}\"). *"
echo "************************************************************************************************************"
