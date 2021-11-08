# Copyright (C) 2019 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.704589");
  script_version("2020-01-07T08:25:23+0000");
  script_cve_id("CVE-2019-3467");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2020-01-07 08:25:23 +0000 (Tue, 07 Jan 2020)");
  script_tag(name:"creation_date", value:"2019-12-20 03:00:13 +0000 (Fri, 20 Dec 2019)");
  script_name("Debian Security Advisory DSA 4589-1 (debian-edu-config - security update)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(9|10)");

  script_xref(name:"URL", value:"https://www.debian.org/security/2019/dsa-4589.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4589-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'debian-edu-config'
  package(s) announced via the DSA-4589-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that debian-edu-config, a set of configuration files
used for the Debian Edu blend, configured too permissive ACLs for the
Kerberos admin server, which allowed password changes for other user
principals.");

  script_tag(name:"affected", value:"'debian-edu-config' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For the oldstable distribution (stretch), this problem has been fixed
in version 1.929+deb9u4.

For the stable distribution (buster), this problem has been fixed in
version 2.10.65+deb10u3.

We recommend that you upgrade your debian-edu-config packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"debian-edu-config", ver:"1.929+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"debian-edu-config", ver:"2.10.65+deb10u3", rls:"DEB10"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);