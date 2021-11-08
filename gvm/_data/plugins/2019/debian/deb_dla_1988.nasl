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
  script_oid("1.3.6.1.4.1.25623.1.0.891988");
  script_version("2020-01-29T08:22:52+0000");
  script_cve_id("CVE-2019-12385", "CVE-2019-12386");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-01-29 08:22:52 +0000 (Wed, 29 Jan 2020)");
  script_tag(name:"creation_date", value:"2019-11-12 03:00:55 +0000 (Tue, 12 Nov 2019)");
  script_name("Debian LTS: Security Advisory for ampache (DLA-1988-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2019/11/msg00008.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-1988-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ampache'
  package(s) announced via the DLA-1988-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in Ampache, a web-based audio
file management system.

CVE-2019-12385

A stored XSS exists in the localplay.php LocalPlay 'add instance'
functionality. The injected code is reflected in the instances menu.
This vulnerability can be abused to force an admin to create a new
privileged user whose credentials are known by the attacker.

CVE-2019-12386

The search engine is affected by a SQL Injection, so any user able
to perform lib/class/search.class.php searches (even guest users)
can dump any data contained in the database (sessions, hashed
passwords, etc.). This may lead to a full compromise of admin
accounts, when combined with the weak password generator algorithm
used in the lostpassword functionality.");

  script_tag(name:"affected", value:"'ampache' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 8 'Jessie', these problems have been fixed in version
3.6-rzb2752+dfsg-5+deb8u1.

We recommend that you upgrade your ampache packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"ampache", ver:"3.6-rzb2752+dfsg-5+deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ampache-common", ver:"3.6-rzb2752+dfsg-5+deb8u1", rls:"DEB8"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
