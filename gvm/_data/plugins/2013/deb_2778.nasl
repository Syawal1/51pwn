# OpenVAS Vulnerability Test
# Auto-generated from advisory DSA 2778-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH http://greenbone.net
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
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
#

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702778");
  script_version("2020-11-19T10:53:01+0000");
  script_cve_id("CVE-2013-4365");
  script_name("Debian Security Advisory DSA 2778-1 (libapache2-mod-fcgid - heap-based buffer overflow)");
  script_tag(name:"last_modification", value:"2020-11-19 10:53:01 +0000 (Thu, 19 Nov 2020)");
  script_tag(name:"creation_date", value:"2013-10-12 00:00:00 +0200 (Sat, 12 Oct 2013)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_xref(name:"URL", value:"http://www.debian.org/security/2013/dsa-2778.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(6|7)");
  script_tag(name:"affected", value:"libapache2-mod-fcgid on Debian Linux");
  script_tag(name:"solution", value:"For the oldstable distribution (squeeze), this problem has been fixed in
version 1:2.3.6-1+squeeze2.

For the stable distribution (wheezy), this problem has been fixed in
version 1:2.3.6-1.2+deb7u1.

For the unstable distribution (sid), this problem has been fixed in
version 1:2.3.9-1.

We recommend that you upgrade your libapache2-mod-fcgid packages.");
  script_tag(name:"summary", value:"Robert Matthews discovered that the Apache FCGID module, a FastCGI
implementation for Apache HTTP Server, fails to perform adequate
boundary checks on user-supplied input. This may allow a remote attacker
to cause a heap-based buffer overflow, resulting in a denial of service
or potentially allowing the execution of arbitrary code.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"libapache2-mod-fcgid", ver:"1:2.3.6-1+squeeze2", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libapache2-mod-fcgid-dbg", ver:"1:2.3.6-1+squeeze2", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libapache2-mod-fcgid", ver:"1:2.3.6-1.2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libapache2-mod-fcgid-dbg", ver:"1:2.3.6-1.2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}