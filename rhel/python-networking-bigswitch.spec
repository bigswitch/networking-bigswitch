%global pypi_name networking-bigswitch
%global pypi_name_underscore networking_bigswitch
%global rpm_name networking-bigswitch
%global rpm_prefix openstack-neutron-bigswitch
%global docpath doc/build/html
%global lib_dir %{buildroot}%{python2_sitelib}/%{pypi_name}/plugins/bigswitch

Name:           python-%{rpm_name}
Version:        10.0.5
Release:        1%{?dist}
Epoch:          1
Summary:        Big Switch Networks neutron plugin for OpenStack Networking
License:        ASL 2.0
URL:            https://pypi.python.org/pypi/%{pypi_name}
Source0:        https://pypi.python.org/packages/source/b/%{pypi_name}/%{pypi_name}-%{version}.tar.gz
Source1:        neutron-bsn-agent.service
Source2:        neutron-bsn-lldp.service
BuildArch:      noarch

BuildRequires:  python-devel
BuildRequires:  python-pbr
BuildRequires:  python-setuptools
BuildRequires:  python-sphinx
BuildRequires:  systemd-units

Requires:       openstack-neutron-common >= 1:7.0.0
Requires:       python-pbr >= 0.10.8
Requires:       python-oslo-log >= 1.0.0
Requires:       python-oslo-config >= 2:1.9.3
Requires:       python-oslo-utils >= 1.4.0
Requires:       python-oslo-messaging >= 1.8.0
Requires:       python-oslo-serialization >= 1.4.0

Requires(post):   systemd
Requires(preun):  systemd
Requires(postun): systemd

%description
This package contains Big Switch Networks
neutron plugins and agents

%package -n %{rpm_prefix}-agent
Summary:        Neutron Big Switch Networks agent
Requires:       python-%{rpm_name} = %{epoch}:%{version}-%{release}

%description -n %{rpm_prefix}-agent
This package contains the Big Switch Networks
neutron agent for security groups.

%package -n %{rpm_prefix}-lldp
Summary:        Neutron Big Switch Networks LLDP service
Requires:       python-%{rpm_name} = %{epoch}:%{version}-%{release}

%description -n %{rpm_prefix}-lldp
This package contains the Big Switch Networks neutron LLDP agent.

%package doc
Summary:        Neutron Big Switch Networks plugin documentation

%description doc
This package contains the documentation for
Big Switch Networks neutron plugins.

%prep
%setup -q -n %{pypi_name}-%{version}

%build
export PBR_VERSION=%{version}
export SKIP_PIP_INSTALL=1
%{__python2} setup.py build
%{__python2} setup.py build_sphinx
rm %{docpath}/.buildinfo

%install
%{__python2} setup.py install --skip-build --root %{buildroot}
install -p -D -m 644 %{SOURCE1} %{buildroot}%{_unitdir}/neutron-bsn-agent.service
install -p -D -m 644 %{SOURCE2} %{buildroot}%{_unitdir}/neutron-bsn-lldp.service
mkdir -p %{buildroot}/%{_sysconfdir}/neutron/conf.d/neutron-bsn-agent
mkdir -p %{lib_dir}/tests
for lib in %{lib_dir}/version.py %{lib_dir}/tests/test_server.py; do
    sed '1{\@^#!/usr/bin/env python@d}' $lib > $lib.new &&
    touch -r $lib $lib.new &&
    mv $lib.new $lib
done

%files
%license LICENSE
%{python2_sitelib}/%{pypi_name}
%{python2_sitelib}/%{pypi_name_underscore}
%{python2_sitelib}/*.egg-info

%config %{_sysconfdir}/neutron/policy.d/bsn_plugin_policy.json

%files -n %{rpm_prefix}-agent
%license LICENSE
%{_unitdir}/neutron-bsn-agent.service
%{_bindir}/neutron-bsn-agent
%dir %{_sysconfdir}/neutron/conf.d/neutron-bsn-agent

%files -n %{rpm_prefix}-lldp
%license LICENSE
%{_unitdir}/neutron-bsn-lldp.service
%{_bindir}/bsnlldp

%files doc
%license LICENSE
%doc README.rst
%doc %{docpath}

%post
%systemd_post neutron-bsn-agent.service
%systemd_post neutron-bsn-lldp.service

%preun
%systemd_preun neutron-bsn-agent.service
%systemd_preun neutron-bsn-lldp.service

%postun
%systemd_postun_with_restart neutron-bsn-agent.service
%systemd_postun_with_restart neutron-bsn-lldp.service

%changelog
* Tue Mar 28 2017 Aditya Vaja <aditya.vaja@bigswitch.com> - 10.0.4
- OSP-51: add/remove router_interface transaction hack
- OSP-50: make amends for rename tenant to project
- bump version for UT failure fix
* Wed Mar 22 2017 Aditya Vaja <aditya.vaja@bigswitch.com> - 10.0.3
- ensure keystone_auth is correctly fetched
* Tue Mar 21 2017 Aditya Vaja <aditya.vaja@bigswitch.com> - 10.0.2
- ensure MLR changes are included
* Fri Mar 10 2017 Aditya Vaja <aditya.vaja@bigswitch.com> - 10.0.1
- branch off for stable/ocata
- Revert "Revert OSP-6 support MLR in bsnstacklib"
* Mon Mar 06 2017 Aditya Vaja <aditya.vaja@bigswitch.com> - 10.0.0
- Revert OSP-6 support MLR in bsnstacklib
* Mon Jan 23 2017 Aditya Vaja <aditya.vaja@bigswitch.com> - 10.0.0.0b2
- OSP-6 support MLR in bsnstacklib
