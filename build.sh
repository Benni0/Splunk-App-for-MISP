#! /bin/bash

cp README.md ./package/README.txt
cp LICENSE.txt ./package/
ucc-gen build
slim package output/TA_misp
rm ./package/README.txt
rm ./package/LICENSE.txt
