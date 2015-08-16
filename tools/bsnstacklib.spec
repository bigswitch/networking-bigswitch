%global pypi_name bsnstacklib

Name:           python-%{pypi_name}
Version:        2015.1.29
Release:        1%{?dist}
Summary:        Big Switch Networks Plugins for OpenStack Networking

License:        ASL %(TODO: version)s
URL:            http://www.bigswitch.com/
Source0:        https://pypi.python.org/packages/source/b/%{pypi_name}/%{pypi_name}-%{version}.tar.gz
BuildArch:      noarch

BuildRequires:  python-devel
BuildRequires:  python-pbr
BuildRequires:  python-sphinx

Requires: python-pbr
Requires: python-sphinx

%description
This library contains the components required to integrate an
OpenStack deployment with a Big Switch Networks fabric.

%prep
%setup -q -n %{pypi_name}-%{version}
# Remove bundled egg-info
rm -rf %{pypi_name}.egg-info
# generate html docs
sphinx-build doc/source html
# remove the sphinx-build leftovers
rm -rf html/.{doctrees,buildinfo}


%build
%{__python2} setup.py build


%install
%{__python2} setup.py install --skip-build --root %{buildroot}


%files
%doc html README.rst LICENSE
%{python2_sitelib}/%{pypi_name}
%{python2_sitelib}/%{pypi_name}-%{version}-py?.?.egg-info
/usr/bin/neutron-bsn-agent
/usr/etc/neutron/plugins/bigswitch/restproxy.ini
/usr/etc/neutron/plugins/bigswitch/ssl/ca_certs/README
/usr/etc/neutron/plugins/bigswitch/ssl/host_certs/README
/usr/etc/neutron/plugins/ml2/restproxy.ini
/usr/etc/neutron/policy.json


%changelog
* Fri Aug 14 2015 Xin Wu <xin.wu@bigswitch.com> - 2014.2.39-1
- Initial package.

