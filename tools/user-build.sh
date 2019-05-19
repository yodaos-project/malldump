#!/bin/bash

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

main()
{
    do_build extlibc
    do_build malldump
}
