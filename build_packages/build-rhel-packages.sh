#!/bin/bash -eux

DOCKER_IMAGE=$DOCKER_REGISTRY'/horizon-bsn-builder:latest'
BUILD_OS=centos7-x86_64

docker pull $DOCKER_IMAGE

BUILDDIR=$(mktemp -d)
mkdir -p $BUILDDIR/{BUILD,BUILDROOT,RPMS,SOURCES,SPECS,SRPMS}

# update spec file with correct version number and changelog
# NOTE update refs/tags/10.*.* according to version string for each branch
# latest version
CURR_VERSION=`git for-each-ref refs/tags/9.*.* --sort="-*committerdate" --format="%(refname:short)" --count=1`
# get changelog for tags
CHANGE_LOG=`git for-each-ref refs/tags/9.*.* --sort="-*committerdate" --format="* %(*committerdate:local) %(*authorname) %(*authoremail) - %(refname:short)%0a- %(subject)"`
# replace newline chars with \n
CHANGE_LOG="${CHANGE_LOG//$'\n'/\\n}"
# remove timestamp from changelog string
CHANGE_LOG=`echo "$CHANGE_LOG" | sed -E "s/[0-9]{2}:[0-9]{2}:[0-9]{2}\ //g"`
# replace variables in spec file
sed -i -e "s/\${version_number}/$CURR_VERSION/" -e "s/\${change_log}/$CHANGE_LOG/" rhel/python-networking-bigswitch.spec

cp dist/* $BUILDDIR/SOURCES/
cp rhel/*.service $BUILDDIR/SOURCES/
cp rhel/*.spec $BUILDDIR/SPECS/
cp build_packages/build-rhel-packages-inner.sh $BUILDDIR/build-rhel-packages-inner.sh

docker run -v $BUILDDIR:/rpmbuild $DOCKER_IMAGE /rpmbuild/build-rhel-packages-inner.sh

# Copy built RPMs to pkg/
OUTDIR=$(readlink -m "pkg/$BUILD_OS/$GIT_BRANCH/$CURR_VERSION")
rm -rf "$OUTDIR" && mkdir -p "$OUTDIR"
mv $BUILDDIR/SRPMS/*.rpm "$OUTDIR"
mv $BUILDDIR/RPMS/noarch/*.rpm "$OUTDIR"
cp dist/*.tar.gz "$OUTDIR"
git log > "$OUTDIR/gitlog.txt"
touch "$OUTDIR/build-$CURR_VERSION"
ln -snf $(basename $OUTDIR) $OUTDIR/../latest

rm -rf "$BUILDDIR"
