#!/bin/bash

malldump()
{
    mkdir -p $PROJECT_DIR/build && cd $PROJECT_DIR/build
    cmake .. -DBUILD_DEBUG=$DEBUG && make -j$JOBS
    [ ! $? -eq 0 ] && exit 1
}

main()
{
    do_build malldump
}
