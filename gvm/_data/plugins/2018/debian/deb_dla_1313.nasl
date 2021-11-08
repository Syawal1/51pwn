# Copyright (C) 2018 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) of the respective author(s)
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.891313");
  script_version("2020-01-29T08:22:52+0000");
  script_cve_id("CVE-2018-5732", "CVE-2018-5733");
  script_name("Debian LTS: Security Advisory for isc-dhcp (DLA-1313-1)");
  script_tag(name:"last_modification", value:"2020-01-29 08:22:52 +0000 (Wed, 29 Jan 2020)");
  script_tag(name:"creation_date", value:"2018-03-27 00:00:00 +0200 (Tue, 27 Mar 2018)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2018/03/msg00015.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_tag(name:"affected", value:"isc-dhcp on Debian Linux");

  script_tag(name:"solution", value:"For Debian 7 'Wheezy', these problems have been fixed in version
4.2.2.dfsg.1-5+deb70u9.

We recommend that you upgrade your isc-dhcp packages.");

  script_tag(name:"summary", value:"Several vulnerabilities have been discovered in the ISC DHCP client,
relay and server. The Common Vulnerabilities and Exposures project
identifies the following issues:

CVE-2018-5732

Felix Wilhelm of the Google Security Team discovered that the DHCP
client is prone to an out-of-bound memory access vulnerability when
processing specially constructed DHCP options responses, resulting
in potential execution of arbitrary code by a malicious DHCP server.

CVE-2018-5733

Felix Wilhelm of the Google Security Team discovered that the DHCP
server does not properly handle reference counting when processing
client requests. A malicious client can take advantage of this flaw
to cause a denial of service (dhcpd crash) by sending large amounts
of traffic.");

  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"isc-dhcp-client", ver:"4.2.2.dfsg.1-5+deb70u9", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"isc-dhcp-client-dbg", ver:"4.2.2.dfsg.1-5+deb70u9", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"isc-dhcp-common", ver:"4.2.2.dfsg.1-5+deb70u9", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"isc-dhcp-dev", ver:"4.2.2.dfsg.1-5+deb70u9", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"isc-dhcp-relay", ver:"4.2.2.dfsg.1-5+deb70u9", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"isc-dhcp-relay-dbg", ver:"4.2.2.dfsg.1-5+deb70u9", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"isc-dhcp-server", ver:"4.2.2.dfsg.1-5+deb70u9", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"isc-dhcp-server-dbg", ver:"4.2.2.dfsg.1-5+deb70u9", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"isc-dhcp-server-ldap", ver:"4.2.2.dfsg.1-5+deb70u9", rls:"DEB7"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}