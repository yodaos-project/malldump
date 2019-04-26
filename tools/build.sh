#!/bin/bash

# usage
usage()
{
	echo -e "USAGE: $0 [ARCH]"
	echo -e "\tARCH   arm | x86, [default: x86]"
	echo -e ".e.g: $0"
	echo -e ".e.g: $0 x86"
}
[[ "$*" =~ "help" ]] && usage && exit -1

# logging aspect
do_build()
{
	echo -e "\033[32m($(date '+%Y-%m-%d %H:%M:%S')): Building $1\033[0m"
	$*
	echo -e "\033[32m($(date '+%Y-%m-%d %H:%M:%S')): Finished $1\033[0m"
}

# change directory to the location of this script
ORIGIN_DIR=$(pwd)
SCRIPT_DIR=$(cd `dirname $0`; pwd)
PROJECT_DIR=$SCRIPT_DIR/../

# parse options
ARCH=x86 && [ -n "$1" ] && ARCH=$1
[ -z "$JOBS" ] &&  JOBS=1
[[ "$OSTYPE" == "linux-gnu" ]] && ((JOBS=$(grep -c ^processor /proc/cpuinfo)-1))

# setup cross-chain
export PKG_CONFIG_PATH=$PROJECT_DIR/lib/pkgconfig
if [ "$ARCH" = "arm" ]; then
	export CC=/opt/arm/bin/arm-linux-gnueabi-gcc
	export CXX=/opt/arm/bin/arm-linux-gnueabi-g++
	export STRIP=/opt/arm/bin/arm-linux-gnueabi-strip
	export AR=/opt/arm/bin/arm-linux-gnueabi-ar
else
	export CC=gcc
	export CXX=g++
	export STRIP=strip
	export AR=ar
fi

libgtest()
{
	libgtest_path=$PROJECT_DIR/deps/googletest

	if [ ! "$(find $PROJECT_DIR/lib -maxdepth 1 -name ${FUNCNAME[0]}*)" ]; then
		mkdir -p $libgtest_path/build && cd $libgtest_path/build
		cmake .. -DCMAKE_INSTALL_PREFIX:PATH=$PROJECT_DIR
		make -j$JOBS && make install
	fi
}

malldump()
{
	mkdir -p $PROJECT_DIR/build && cd $PROJECT_DIR/build
	cmake .. && make -j$JOBS
}

git submodule init
git submodule update

do_build libgtest
do_build malldump
