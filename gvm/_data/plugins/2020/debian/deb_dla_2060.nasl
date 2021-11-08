# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.892060");
  script_version("2020-01-29T08:22:52+0000");
  script_cve_id("CVE-2020-5504");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-01-29 08:22:52 +0000 (Wed, 29 Jan 2020)");
  script_tag(name:"creation_date", value:"2020-01-16 04:00:05 +0000 (Thu, 16 Jan 2020)");
  script_name("Debian LTS: Security Advisory for phpmyadmin (DLA-2060-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2020/01/msg00011.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2060-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/948718");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'phpmyadmin'
  package(s) announced via the DLA-2060-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"In phpMyAdmin 4 before 4.9.4 and 5 before 5.0.1, SQL injection exists in the
user accounts page. A malicious user could inject custom SQL in place of their
own username when creating queries to this page. An attacker must have a valid
MySQL account to access the server.");

  script_tag(name:"affected", value:"'phpmyadmin' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 8 'Jessie', this problem has been fixed in version
4:4.2.12-2+deb8u8.

We recommend that you upgrade your phpmyadmin packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"phpmyadmin", ver:"4:4.2.12-2+deb8u8", rls:"DEB8"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
