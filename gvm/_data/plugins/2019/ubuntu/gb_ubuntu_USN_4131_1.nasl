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
  script_oid("1.3.6.1.4.1.25623.1.0.844173");
  script_version("2019-09-16T07:48:47+0000");
  script_cve_id("CVE-2019-13962", "CVE-2019-14437", "CVE-2019-14438", "CVE-2019-14498", "CVE-2019-14533", "CVE-2019-14534", "CVE-2019-14535", "CVE-2019-14776", "CVE-2019-14777", "CVE-2019-14778", "CVE-2019-14970");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-09-16 07:48:47 +0000 (Mon, 16 Sep 2019)");
  script_tag(name:"creation_date", value:"2019-09-12 02:01:23 +0000 (Thu, 12 Sep 2019)");
  script_name("Ubuntu Update for vlc USN-4131-1");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=(UBUNTU18\.04 LTS|UBUNTU19\.04)");

  script_xref(name:"USN", value:"4131-1");
  script_xref(name:"URL", value:"https://lists.ubuntu.com/archives/ubuntu-security-announce/2019-September/005114.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'vlc'
  package(s) announced via the USN-4131-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that VLC incorrectly handled certain media files. If a
user were tricked into opening a specially-crafted file, a remote attacker
could use this issue to cause VLC to crash, resulting in a denial of
service, or possibly execute arbitrary code.");

  script_tag(name:"affected", value:"'vlc' package(s) on Ubuntu 19.04, Ubuntu 18.04 LTS.");

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

  if(!isnull(res = isdpkgvuln(pkg:"vlc", ver:"3.0.8-0ubuntu18.04.1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if (__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU19.04") {

  if(!isnull(res = isdpkgvuln(pkg:"vlc", ver:"3.0.8-0ubuntu19.04.1", rls:"UBUNTU19.04"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if (__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);