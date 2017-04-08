%global pypi_name bsnstacklib
%global rpm_name networking-bigswitch
%global rpm_prefix openstack-neutron-bigswitch
%global docpath doc/build/html
%global lib_dir %{buildroot}%{python2_sitelib}/%{pypi_name}/plugins/bigswitch

Name:           python-%{rpm_name}
Version:        20153.36.11
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
* Fri Apr 07 2017 Aditya Vaja <aditya.vaja@bigswitch.com> - 20153.36.10
- BVS-5916: handle special characters in object names
- OSP-45: improve error visibility on GUI
* Wed Mar 1 2017 Sarath Kumar <sarath@bigswitch.com> - 20153.36.10
- BVS-7525: bsnstacklib: don't sync dangling objects to BCF
* Mon Feb 14 2017 Aditya Vaja <aditya.vaja@bigswitch.com> - 20153.36.9
- OSP-33: allow uuid style names for openstack objects
- OSP-22 update existing policy number with 14000
- OSP-20 send updated tenant rules during topo sync
- OSP-14 ensure router update doesn't overwrite existing policies
* Mon Jan 23 2017 Aditya Vaja <aditya.vaja@bigswitch.com> - 20153.36.8
- OSP-6 support MLR in bsnstacklib
* Thu Dec 1 2016 Aditya/Sarath Kumar - 20153.36.7
- BVS-6548: Raise exception when creating objects with illegal name chars
* Thu Dec 1 2016 Sarath Kumar <sarath@bigswitch.com> - 20153.36.6
- BVS-7488 bsnstacklib: set MTU of all IVS (and related) interfaces to Jumbo
* Tue Jun 28 2016 Aditya Vaja <aditya.vaja@bigswitch.com> - 20153.36.3-1
- BVS-6563 allow non admin user to assign floating IP
* Sat Jun 18 2016 Aditya Vaja <aditya.vaja@bigswitch.com> - 20153.36.1-1
- BVS-6440: allow duplicate testpath names across tenants
* Fri Jun 17 2016 xin wu <xin.wu@bigswitch.com> - 20153.36.0-1
- use new version scheme os_release.bcf_release.bug_fix
* Thu Jun 09 2016 Aditya Vaja <aditya.vaja@bigswitch.com> - 2015.3.17-1
- update policy file for testpath
* Fri May 20 2016 Aditya Vaja <aditya.vaja@bigswitch.com> - 2015.3.14-1
- automate rpm build and packaging
* Mon Apr 11 2016 Xin Wu <xin.wu@bigswitch.com> - 2015.3.12-1
- Fix l3 plugin bug for liberty
* Sat Apr 09 2016 Xin Wu <xin.wu@bigswitch.com> - 2015.3.11-1
- Fix subnet delete in liberty
* Tue Mar 08 2016 Xin Wu <xin.wu@bigswitch.com> - 2015.3.8-1
- Use kilo v2 2015.1.52. Don't send lldp until all uplinks are up
* Tue Mar 08 2016 Xin Wu <xin.wu@bigswitch.com> - 2015.3.8-1
- Use liberty 2015.3.8. Use config instead of file
* Mon Mar 07 2016 Xin Wu <xin.wu@bigswitch.com> - 2015.3.7-1
- Use liberty 2015.3.7. Use config instead of file
* Mon Mar 07 2016 Xin Wu <xin.wu@bigswitch.com> - 2015.3.6-1
- Use liberty 2015.3.6. Add missing policy json file
* Mon Mar 07 2016 Xin Wu <xin.wu@bigswitch.com> - 2015.3.5-1
- Use liberty 2015.3.5. Add missing policy json file
* Mon Mar 07 2016 Xin Wu <xin.wu@bigswitch.com> - 2015.3.4-1
- Use mitaka 2015.3.4. Add missing policy json file
* Wed Feb 10 2016 Xin Wu <xin.wu@bigswitch.com> - 2015.3.3-1
- Use liberty 2015.3.3. Always use iptables for sg
* Wed Feb 03 2016 Xin Wu <xin.wu@bigswitch.com> - 2015.3.2-1
- Fix bug in liberty. Register callback functions for security group
* Mon Feb 01 2016 Xin Wu <xin.wu@bigswitch.com> - 2015.3.1-1
- Fix auth_url for liberty.
* Sat Jan 23 2016 Xin Wu <xin.wu@bigswitch.com> - 2015.3.0-1
- Initial test for liberty
