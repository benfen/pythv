#!/bin/sh

BASEDIR=$(dirname $0)
mkdir -p cve-data

(
    cd ${BASEDIR}/cve-data
    for i in `seq 2002 2019`;
    do
        wget -c "https://nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-${i}.json.zip"
        unzip "nvdcve-1.0-${i}.json.zip"
        rm "nvdcve-1.0-${i}.json.zip"
    done
)
