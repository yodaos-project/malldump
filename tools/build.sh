#!/bin/bash

# usage
usage()
{
    echo -e "usage: TOOLCHAIN=<toolchain prefix> DEBUG=yes $0 "
    echo -e "  TOOLCHAIN    arm-linux-gnueabi, [default: ]"
    echo -e "  DEBUG        on|yes, [default: OFF]"
    echo -e ".e.g: $0"
    echo -e ".e.g: TOOLCHAIN=arm-linux-gnueabi DEBUG=yes $0"
}
[[ "$*" =~ "help" ]] || [[ "$*" =~ "-h" ]] && usage && exit 2

# change directory to the location of this script
ORIGIN_DIR=$(pwd)
SCRIPT_DIR=$(cd `dirname $0`; pwd)
PROJECT_DIR=$SCRIPT_DIR/../

# parse opts & envs
[ -n "$TOOLCHAIN" ] && TOOLCHAIN=${TOOLCHAIN}-
[ -z "$DEBUG" ] && DEBUG=OFF
[ -z "$JOBS" ] &&  JOBS=1
[[ "$OSTYPE" == "linux-gnu" ]] && ((JOBS=$(grep -c ^processor /proc/cpuinfo)-1))

# setup cross toolchain
export PKG_CONFIG_PATH=$PROJECT_DIR/lib/pkgconfig
export CC=${TOOLCHAIN}gcc
export CXX=${TOOLCHAIN}g++
export AR=${TOOLCHAIN}ar
export LD=${TOOLCHAIN}ld
export STRIP=${TOOLCHAIN}strip

# logging aspect
do_build()
{
    echo -e "\033[32m($(date '+%Y-%m-%d %H:%M:%S')): Building $1\033[0m"
    $*
    echo -e "\033[32m($(date '+%Y-%m-%d %H:%M:%S')): Finished $1\033[0m"
}

# initialization
do_init()
{
    git submodule init
    git submodule update

    [ ! -e $PROJECT_DIR/lib ] && mkdir -p $PROJECT_DIR/lib && ln -sf lib lib64
}

extlibc()
{
    extlibc_path=$PROJECT_DIR/deps/extlibc

    if [ ! "$(find $PROJECT_DIR/lib* -maxdepth 1 -name *${FUNCNAME[0]}*)" ]; then
        mkdir -p $extlibc_path/build && cd $extlibc_path/build
        cmake .. -DCMAKE_INSTALL_PREFIX:PATH=$PROJECT_DIR
        make -j$JOBS && make install
        [ ! $? -eq 0 ] && exit 1
    fi
}

malldump()
{
    mkdir -p $PROJECT_DIR/build && cd $PROJECT_DIR/build
    cmake .. -DBUILD_DEBUG=$DEBUG && make -j$JOBS
    [ ! $? -eq 0 ] && exit 1
}

do_init
do_build extlibc
do_build malldump
