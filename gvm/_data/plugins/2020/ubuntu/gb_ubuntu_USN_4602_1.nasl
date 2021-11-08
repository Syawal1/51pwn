# Copyright (C) 2020 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
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
  script_oid("1.3.6.1.4.1.25623.1.0.844677");
  script_version("2020-10-29T06:27:27+0000");
  script_cve_id("CVE-2020-10543", "CVE-2020-10878", "CVE-2020-12723");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-10-29 06:27:27 +0000 (Thu, 29 Oct 2020)");
  script_tag(name:"creation_date", value:"2020-10-27 04:01:29 +0000 (Tue, 27 Oct 2020)");
  script_name("Ubuntu: Security Advisory for perl (USN-4602-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=(UBUNTU18\.04 LTS|UBUNTU16\.04 LTS|UBUNTU20\.04 LTS)");

  script_xref(name:"USN", value:"4602-1");
  script_xref(name:"URL", value:"https://lists.ubuntu.com/archives/ubuntu-security-announce/2020-October/005718.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'perl'
  package(s) announced via the USN-4602-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"ManhND discovered that Perl incorrectly handled certain regular
expressions. In environments where untrusted regular expressions are
evaluated, a remote attacker could possibly use this issue to cause Perl to
crash, resulting in a denial of service, or possibly execute arbitrary
code. (CVE-2020-10543)

Hugo van der Sanden and Slaven Rezic discovered that Perl incorrectly
handled certain regular expressions. In environments where untrusted
regular expressions are evaluated, a remote attacker could possibly use
this issue to cause Perl to crash, resulting in a denial of service, or
possibly execute arbitrary code. (CVE-2020-10878)

Sergey Aleynikov discovered that Perl incorrectly handled certain regular
expressions. In environments where untrusted regular expressions are
evaluated, a remote attacker could possibly use this issue to cause Perl to
crash, resulting in a denial of service, or possibly execute arbitrary
code. (CVE-2020-12723)");

  script_tag(name:"affected", value:"'perl' package(s) on Ubuntu 20.04 LTS, Ubuntu 18.04 LTS, Ubuntu 16.04 LTS.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "UBUNTU18.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"perl", ver:"5.26.1-6ubuntu0.5", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU16.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"perl", ver:"5.22.1-9ubuntu0.9", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU20.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"perl", ver:"5.30.0-9ubuntu0.2", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);