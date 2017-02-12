#!/usr/bin/env bash

AMAVIS_USER=amavis
SOURCE_DIR=amavis-macro-plugin-master
DESTINATION_DIR=/usr/local/bin

for file_name in mmd.py document.py; do
    destination_file=${DESTINATION_DIR}/${file_name}

    cp ${SOURCE_DIR}/${file_name} ${destination_file}

    chown root:${AMAVIS_USER} ${destination_file}
    chmod 755 ${destination_file}
done

cp ${SOURCE_DIR}/document_config.json ${DESTINATION_DIR}