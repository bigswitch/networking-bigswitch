#!/bin/bash
rm -rf ./*.deb ./*.tar.gz ./*.dsc ./*.changes
rm -rf */*.deb
rm -rf ./plugins/**/build/ ./plugins/**/dist
rm -rf ./plugins/**/lib/networking_bigswitch_*_plugin.egg-info ./plugins/networking_bigswitch-*
