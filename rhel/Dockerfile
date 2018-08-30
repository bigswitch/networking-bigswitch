FROM registry.access.redhat.com/rhosp13/openstack-neutron-server:latest
MAINTAINER Big Switch Networks Inc <rhosp-bugs-internal@bigswitch.com>
LABEL name="rhosp13/openstack-neutron-server-bigswitch" \
      maintainer="rhosp-bugs-internal@bigswitch.com" \
      vendor="Big Switch Networks Inc" \
      version="13.0" \
      release="1" \
      summary="Red Hat OpenStack Platform 13.0 neutron-server Big Switch Networks ML2 Plugin" \
      description="Red Hat OpenStack Platform 13.0 neutron-server Big Switch Networks ML2 Plugin"
# switch to root and install networking-bigswitch from PYPI
USER root
RUN curl "https://bootstrap.pypa.io/get-pip.py" -o "/tmp/get-pip.py"
RUN python /tmp/get-pip.py
RUN pip install --upgrade "networking-bigswitch>=12.0.0,<12.1.0"
# copy License
RUN mkdir /licenses
RUN curl -L -o /licenses/LICENSE https://raw.githubusercontent.com/openstack/networking-bigswitch/master/LICENSE
# switch the container back to the neutron user
USER neutron
