%global pypi_name bsnstacklib
%global rpm_name networking-bigswitch
%global rpm_prefix openstack-neutron-bigswitch
%global docpath doc/build/html
%global lib_dir %{buildroot}%{python2_sitelib}/%{pypi_name}/plugins/bigswitch

Name:           python-%{rpm_name}
Version:        7.0.4
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
* Fri May 20 2016 Aditya Vaja <aditya.vaja@bigswitch.com> 7.0.4
- automate rpm build and packaging
* Mon Apr 11 2016 Xin Wu <xin.wu@bigswitch.com> - 2015.3.12-1
- Fix l3 plugin bug for liberty
* Mon Apr 11 2016 Xin Wu <xin.wu@bigswitch.com> - 2015.1.54-1
- Fix l3 plugin bug for kilo v2
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
* Wed Feb 10 2016 Xin Wu <xin.wu@bigswitch.com> - 2015.1.51-1
- Use kilo v2 2015.1.51. Always use iptables for sg
* Fri Feb 05 2016 Xin Wu <xin.wu@bigswitch.com> - 2015.1.50-1
- Use kilo v2 2015.1.50. Sync default sg to bcf controller
* Wed Feb 03 2016 Xin Wu <xin.wu@bigswitch.com> - 2015.3.2-1
- Fix bug in liberty. Register callback functions for security group
* Wed Feb 03 2016 Xin Wu <xin.wu@bigswitch.com> - 2015.1.49-1
- Use kilo v2 2015.1.49. Register callback functions for security group
* Mon Feb 01 2016 Xin Wu <xin.wu@bigswitch.com> - 2015.3.1-1
- Fix auth_url for liberty.
* Fri Jan 29 2016 Xin Wu <xin.wu@bigswitch.com> - 2015.1.48-1
- Use kilo v2 2015.1.48. Remove dependency on keystone configuration
* Thu Jan 28 2016 Xin Wu <xin.wu@bigswitch.com> - 2015.1.47-1
- Use kilo v2 2015.1.47.
* Tue Jan 26 2016 Xin Wu <xin.wu@bigswitch.com> - 2015.1.46-1
- Use kilo v2 2015.1.46.
* Tue Jan 26 2016 Xin Wu <xin.wu@bigswitch.com> - 2015.2.13-1
- Match kilo v2 2015.1.46. Fix NoneType for security groups
* Sat Jan 23 2016 Xin Wu <xin.wu@bigswitch.com> - 2015.3.0-1
- Initial test for liberty
* Sat Jan 23 2016 Xin Wu <xin.wu@bigswitch.com> - 2015.2.12-1
- Match kilo v2 2015.1.46. Send lldp via both ovs and linux bond
* Sat Jan 09 2016 Xin Wu <xin.wu@bigswitch.com> - 2015.2.11-1
- Match kilo v2 2015.1.45. Fix neutron dependency
* Fri Jan 08 2016 Xin Wu <xin.wu@bigswitch.com> - 2015.2.10-1
- Match kilo v2 2015.1.45. Fix neutron dependency
* Thu Jan 07 2016 Xin Wu <xin.wu@bigswitch.com> - 2015.2.9-1
- Match kilo v2 2015.1.45. Fix neutron dependency
* Wed Jan 06 2016 Xin Wu <xin.wu@bigswitch.com> - 2015.2.8-1
- Match kilo v2 2015.1.45. Fix neutron dependency
* Tue Jan 05 2016 Xin Wu <xin.wu@bigswitch.com> - 2015.2.7-1
- Match kilo v2 2015.1.45. Fix neutron dependency
* Wed Dec 16 2015 Xin Wu <xin.wu@bigswitch.com> - 2015.2.6-1
- Match kilo v2 2015.1.45. Fix neutron dependency
* Sat Dec 12 2015 Xin Wu <xin.wu@bigswitch.com> - 2015.2.5-1
- Match kilo v2 2015.1.45. Fix vrrp for kilo
* Wed Dec 09 2015 Xin Wu <xin.wu@bigswitch.com> - 2015.2.4-1
- Match kilo v2 2015.1.44. Update dependency to openstack-neutron 7.0.0
* Thu Nov 26 2015 Xin Wu <xin.wu@bigswitch.com> - 2015.2.3-1
- Match kilo v2 2015.1.44.
* Tue Nov 24 2015 Xin Wu <xin.wu@bigswitch.com> - 2015.2.2-1
- Match kilo v2 2015.1.43.
* Sat Nov 21 2015 Xin Wu <xin.wu@bigswitch.com> - 2015.2.1-1
- Support kilo v1 api.
* Wed Nov 18 2015 Xin Wu <xin.wu@bigswitch.com> - 2015.1.41-1
- Support new router workflow.
* Sat Oct 17 2015 Xin Wu <xin.wu@bigswitch.com> - 2015.1.40-1
- Bug fix.
* Wed Oct 14 2015 Xin Wu <xin.wu@bigswitch.com> - 2015.1.39-1
- Bug fix with service dependencies.
* Thu Sep 17 2015 Xin Wu <xin.wu@bigswitch.com> - 2015.1.38-1
- Bug fix with security groups.
* Fri Aug 14 2015 Xin Wu <xin.wu@bigswitch.com> - 2015.1.37-1
- Initial package.

