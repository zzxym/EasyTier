#!/bin/sh

version=$(cat module.prop | grep 'version=' | awk -F '=' '{print $2}' | sed 's/ (.*//')

version='v'$(grep '^version =' ../../easytier/Cargo.toml | cut -d '"' -f 2)

if [ -z "$version" ]; then
    echo "Error: 版本号不存在."
    exit 1
fi

filename="sdwan_magisk_${version}.zip"
echo $version  


if [ -f "./sdwan-core" ] && [ -f "./sdwan-cli" ] && [ -f "./sdwan-web" ]; then
    zip -r -o -X "$filename" ./ -x '.git/*' -x '.github/*' -x 'folder/*' -x 'build.sh' -x 'magisk_update.json'
else
    wget -O "sdwan_last.zip" https://github.com/EasyTier/EasyTier/releases/download/"$version"/sdwan-linux-aarch64-"$version".zip
    unzip -o sdwan_last.zip -d ./
    mv ./sdwan-linux-aarch64/* ./
    rm -rf ./sdwan_last.zip
    rm -rf ./sdwan-linux-aarch64
    zip -r -o -X "$filename" ./ -x '.git/*' -x '.github/*' -x 'folder/*' -x 'build.sh' -x 'magisk_update.json'
fi