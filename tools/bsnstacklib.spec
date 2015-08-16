%global pypi_name bsnstacklib
%global rpm_name networking-bigswitch

Name:           python-%{rpm_name}
Version:        2015.1.33
Release:        1%{?dist}
Summary:        Big Switch Networks Plugins for OpenStack Networking

License:        ASL 2.0
URL:            http://www.bigswitch.com/
Source0:        https://pypi.python.org/packages/source/b/%{pypi_name}/%{pypi_name}-%{version}.tar.gz
BuildArch:      noarch

BuildRequires:  python-devel
BuildRequires:  python-pbr
BuildRequires:  python-setuptools
BuildRequires:  python-sphinx

Requires:       python-pbr
Requires:       openstack-neutron

%description
This library contains the components required to integrate an
OpenStack deployment with a Big Switch Networks fabric.

%prep
%setup -q -n %{pypi_name}-%{version}
# Remove bundled egg-info
rm -rf %{pypi_name}.egg-info

%build
%{__python2} setup.py build

%install
%{__python2} setup.py install --skip-build --root %{buildroot}

%files
%license LICENSE
%{python2_sitelib}/%{pypi_name}
%{python2_sitelib}/%{pypi_name}-%{version}-py?.?.egg-info

%changelog
* Fri Aug 14 2015 Xin Wu <xin.wu@bigswitch.com> - 2015.1.33-1
- Initial package.

