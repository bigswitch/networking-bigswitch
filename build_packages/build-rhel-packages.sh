#!/bin/bash -eux
docker.io pull -a wolverineav/horizon-bsn-builder

DOCKER_IMAGE=wolverineav/horizon-bsn-builder:centos7
BUILD_OS=centos7-x86_64
CURR_VERSION=$(awk '/^version/{print $3}' setup.cfg)

BUILDDIR=$(mktemp -d)
mkdir -p $BUILDDIR/{BUILD,BUILDROOT,RPMS,SOURCES,SPECS,SRPMS}

cp dist/* $BUILDDIR/SOURCES/
cp rhel/*.service $BUILDDIR/SOURCES/
cp rhel/*.spec $BUILDDIR/SPECS/
cp build_packages/build-rhel-packages-inner.sh $BUILDDIR/build-rhel-packages-inner.sh

docker.io run -i -t -v $BUILDDIR:/rpmbuild $DOCKER_IMAGE /bin/bash /rpmbuild/build-rhel-packages-inner.sh

# Copy built RPMs to pkg/
OUTDIR=$(readlink -m "pkg/$BUILD_OS/$GIT_BRANCH/$CURR_VERSION")
rm -rf "$OUTDIR" && mkdir -p "$OUTDIR"
mv $BUILDDIR/SRPMS/*.rpm "$OUTDIR"
mv $BUILDDIR/RPMS/noarch/*.rpm "$OUTDIR"
git log > "$OUTDIR/gitlog.txt"
touch "$OUTDIR/build-$CURR_VERSION"
ln -snf $(basename $OUTDIR) $OUTDIR/../latest

rm -rf "$BUILDDIR"
