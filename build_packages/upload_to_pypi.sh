#!/bin/bash -eux
# install twine, to be added to infra puppet script
sudo -H pip install urllib3[secure]
sudo -H pip install twine

# get version info from tags
git fetch --tags
# NOTE update refs/tags/10.*.* according to version string for each branch
CURR_VERSION=`git for-each-ref refs/tags/8.*.* --sort="-*committerdate" --format="%(refname:short)" --count=1`
CURR_SUBJECT=`git for-each-ref refs/tags/8.*.* --sort="-*committerdate" --format="%(subject)" --count=1`

# get pypi and gpg creds in place
mv $PYPIRC_FILE ~/.pypirc
tar -zxvf $GNUPG_TAR -C ~/

echo 'CURR_VERSION=' $CURR_VERSION
echo 'CURR_SUBJECT=' $CURR_SUBJECT
git tag -f -s $CURR_VERSION -m "${CURR_SUBJECT}" -u "Big Switch Networks"

python setup.py sdist

# force success. but always check if pip install fails
twine upload dist/* -r pypi -s -i "Big Switch Networks" || true
# delay of 5 seconds
sleep 5
sudo -H pip install --upgrade networking-bigswitch==$CURR_VERSION
if [ "$?" -eq "0" ]
then
  echo "PYPI upload successful."
else
  echo "PYPI upload FAILED. Check the logs."
fi
# remove the package
sudo -H pip uninstall -y networking-bigswitch

# remove pypi and gpg creds
rm ~/.pypirc
rm -rf ~/.gnupg
