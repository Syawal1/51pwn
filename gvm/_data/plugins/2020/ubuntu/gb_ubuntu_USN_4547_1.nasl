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
  script_oid("1.3.6.1.4.1.25623.1.0.844618");
  script_version("2020-10-01T09:58:23+0000");
  script_cve_id("CVE-2019-15681", "CVE-2018-15127", "CVE-2018-20019", "CVE-2018-20020", "CVE-2018-20021", "CVE-2018-20022", "CVE-2018-20023", "CVE-2018-20024", "CVE-2018-20748", "CVE-2018-20749", "CVE-2018-20750", "CVE-2018-7225");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2020-10-01 09:58:23 +0000 (Thu, 01 Oct 2020)");
  script_tag(name:"creation_date", value:"2020-09-29 03:01:07 +0000 (Tue, 29 Sep 2020)");
  script_name("Ubuntu: Security Advisory for italc (USN-4547-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU18\.04 LTS");

  script_xref(name:"USN", value:"4547-1");
  script_xref(name:"URL", value:"https://lists.ubuntu.com/archives/ubuntu-security-announce/2020-September/005659.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'italc'
  package(s) announced via the USN-4547-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that an information disclosure vulnerability existed in the
LibVNCServer vendored in iTALC when sending a ServerCutText message. An
attacker could possibly use this issue to expose sensitive information.
(CVE-2019-15681)

It was discovered that the LibVNCServer and LibVNCClient vendored in iTALC
incorrectly handled certain packet lengths. A remote attacker could possibly
use this issue to obtain sensitive information, cause a denial of service, or
execute arbitrary code.
(CVE-2018-15127 CVE-2018-20019, CVE-2018-20020, CVE-2018-20021, CVE-2018-20022,
CVE-2018-20023, CVE-2018-20024, CVE-2018-20748, CVE-2018-20749, CVE-2018-20750,
CVE-2018-7225, CVE-2019-15681)");

  script_tag(name:"affected", value:"'italc' package(s) on Ubuntu 18.04 LTS.");

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

  if(!isnull(res = isdpkgvuln(pkg:"italc-client", ver:"1:3.0.3+dfsg1-3ubuntu0.1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"italc-master", ver:"1:3.0.3+dfsg1-3ubuntu0.1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libitalccore", ver:"1:3.0.3+dfsg1-3ubuntu0.1", rls:"UBUNTU18.04 LTS"))) {
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