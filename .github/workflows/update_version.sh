#!/bin/sh

echo $1 > VERSION && 
    sed -i "s/^\(#define UCALL_VERSION_MAJOR \).*/\1$(echo "$1" | cut -d. -f1)/" ./include/ucall/ucall.h &&
    sed -i "s/^\(#define UCALL_VERSION_MINOR \).*/\1$(echo "$1" | cut -d. -f2)/" ./include/ucall/ucall.h &&
    sed -i "s/^\(#define UCALL_VERSION_PATCH \).*/\1$(echo "$1" | cut -d. -f3)/" ./include/ucall/ucall.h &&
    sed -i "s/VERSION [0-9]\+\.[0-9]\+\.[0-9]\+/VERSION $1/" CMakeLists.txt
