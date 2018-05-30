#!/usr/bin/env bash

set -ex

if [ $TRAVIS_OS_NAME == osx ]; then
    brew update
    brew install clang-format ninja

    curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py
    sudo python get-pip.py

    sudo pip install --upgrade pip
    sudo pip install dmgbuild
fi


if [ $TRAVIS_OS_NAME == linux ]; then
    sudo add-apt-repository -y ppa:george-edison55/cmake-3.x
    sudo add-apt-repository -y ppa:chris-lea/libsodium
    sudo apt-get update -qq
    sudo apt-get install -qq -y \
        cmake \
        libsodium-dev
fi
