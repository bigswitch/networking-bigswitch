#!/bin/bash -eux

# RPM runs as root and doesn't like source files owned by a random UID
OUTER_UID=$(stat -c '%u' /networking-bigswitch)
OUTER_GID=$(stat -c '%g' /networking-bigswitch)
trap "chown -R $OUTER_UID:$OUTER_GID /networking-bigswitch" EXIT
chown -R root:root /networking-bigswitch

cd /networking-bigswitch
git config --global user.name "Big Switch Networks"
git config --global user.email "support@bigswitch.com"

# get version info from tags
# git fetch --tags
# NOTE update refs/tags/9.*.* according to version string for each branch
CURR_VERSION=`git for-each-ref refs/tags/9.*.* --sort="-*committerdate" --format="%(refname:short)" --count=1`
CURR_SUBJECT=`git for-each-ref refs/tags/9.*.* --sort="-*committerdate" --format="%(subject)" --count=1`

echo 'CURR_VERSION=' $CURR_VERSION
echo 'CURR_SUBJECT=' $CURR_SUBJECT
git tag -f -s $CURR_VERSION -m "${CURR_SUBJECT}" -u "Big Switch Networks"

python setup.py sdist

# force success. but always check if pip install fails
twine upload dist/* -r pypi -s -i "Big Switch Networks" || true
# delay of 10 seconds
sleep 10
pip install --upgrade networking-bigswitch==$CURR_VERSION
if [ "$?" -eq "0" ]
then
  echo "PYPI upload successful."
else
  echo "PYPI upload FAILED. Check the logs."
fi
# remove the package
pip uninstall -y networking-bigswitch

# revert the permissions
chown -R $OUTER_UID:$OUTER_GID /networking-bigswitch
