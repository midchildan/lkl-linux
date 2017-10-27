#!/bin/sh

PKG_WORKDIR=$(pwd)/deb
LKL_VERSION=4.13.0
PKG_SERIAL=$(date +%Y%m%d)

mkdir -p ${PKG_WORKDIR}/DEBIAN
mkdir -p ${PKG_WORKDIR}/usr/bin
mkdir -p ${PKG_WORKDIR}/usr/lib

cat << EOF > ${PKG_WORKDIR}/DEBIAN/control
Package: lkl
Maintainer: Hajime Tazaki <thehajime@gmail.com>
Architecture: amd64
Version: ${LKL_VERSION}-${PKG_SERIAL}
Description: Linux Kernel Library with hijack library runtime
Depends: libc6
EOF

/bin/cp -fp tools/lkl/liblkl-hijack.so ${PKG_WORKDIR}/usr/lib
/bin/cp -fp tools/lkl/bin/lkl-hijack.sh ${PKG_WORKDIR}/usr/bin/lkl-hijack

# build .deb/.rpm
sudo apt-get install -y alien
fakeroot dpkg-deb --build ${PKG_WORKDIR}/ .
fakeroot alien --bump 0 -r lkl_${LKL_VERSION}-${PKG_SERIAL}_amd64.deb

mkdir -p ${PKG_WORKDIR}/pkgs
/bin/cp -fp *.deb *.rpm ${PKG_WORKDIR}/pkgs
