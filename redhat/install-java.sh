#!/bin/bash

ARCH=`arch`
if [[ ${ARCH} = x86_64 ]]; then
    ARCH=x64
else
    ARCH=s390x
fi

cd /opt

# wget https://github.com/AdoptOpenJDK/semeru11-binaries/releases/download/jdk-11.0.12%2B7_openj9-0.27.0/ibm-semeru-open-jdk_${ARCH}_linux_11.0.12_7_openj9-0.27.0.tar.gz
# tar xzf ibm-semeru-open-jdk_${ARCH}_linux_11.0.12_7_openj9-0.27.0.tar.gz
# rm -rf ibm-semeru-open-jdk_${ARCH}_linux_11.0.12_7_openj9-0.27.0.tar.gz

wget https://github.com/AdoptOpenJDK/semeru11-binaries/releases/download/jdk-11.0.12%2B7_openj9-0.27.0/ibm-semeru-open-jre_${ARCH}_linux_11.0.12_7_openj9-0.27.0.tar.gz
tar xzf ibm-semeru-open-jre_${ARCH}_linux_11.0.12_7_openj9-0.27.0.tar.gz
rm -rf ibm-semeru-open-jre_${ARCH}_linux_11.0.12_7_openj9-0.27.0.tar.gz
