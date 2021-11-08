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
  script_oid("1.3.6.1.4.1.25623.1.0.844711");
  script_version("2020-11-19T07:38:10+0000");
  script_cve_id("CVE-2020-8695", "CVE-2020-8696", "CVE-2020-8698");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2020-11-19 07:38:10 +0000 (Thu, 19 Nov 2020)");
  script_tag(name:"creation_date", value:"2020-11-12 04:00:35 +0000 (Thu, 12 Nov 2020)");
  script_name("Ubuntu: Security Advisory for intel-microcode (USN-4628-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=(UBUNTU20\.04 LTS|UBUNTU18\.04 LTS|UBUNTU16\.04 LTS|UBUNTU20\.10)");

  script_xref(name:"USN", value:"4628-2");
  script_xref(name:"URL", value:"https://lists.ubuntu.com/archives/ubuntu-security-announce/2020-November/005757.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'intel-microcode'
  package(s) announced via the USN-4628-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-4628-1 provided updated Intel Processor Microcode. Unfortunately,
that update prevented certain processors in the Intel Tiger Lake family
from booting successfully. This update reverts the microcode update for
the Tiger Lake processor family.

Please note that the 'dis_ucode_ldr' kernel command line option can be
added in the boot menu to disable microcode loading for system recovery.

We apologize for the inconvenience.

Original advisory details:

Moritz Lipp, Michael Schwarz, Andreas Kogler, David Oswald, Catherine
Easdon, Claudio Canella, and Daniel Gruss discovered that the Intel Running
Average Power Limit (RAPL) feature of some Intel processors allowed a side-
channel attack based on power consumption measurements. A local attacker
could possibly use this to expose sensitive information. (CVE-2020-8695)

Ezra Caltum, Joseph Nuzman, Nir Shildan and Ofir Joseff discovered that
some Intel(R) Processors did not properly remove sensitive information
before storage or transfer in some situations. A local attacker could
possibly use this to expose sensitive information. (CVE-2020-8696)

Ezra Caltum, Joseph Nuzman, Nir Shildan and Ofir Joseff discovered that
some Intel(R) Processors did not properly isolate shared resources in some
situations. A local attacker could possibly use this to expose sensitive
information. (CVE-2020-8698)");

  script_tag(name:"affected", value:"'intel-microcode' package(s) on Ubuntu 20.10, Ubuntu 20.04 LTS, Ubuntu 18.04 LTS, Ubuntu 16.04 LTS.");

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

if(release == "UBUNTU20.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"intel-microcode", ver:"3.20201110.0ubuntu0.20.04.2", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU18.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"intel-microcode", ver:"3.20201110.0ubuntu0.18.04.2", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"intel-microcode", ver:"3.20201110.0ubuntu0.16.04.2", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU20.10") {

  if(!isnull(res = isdpkgvuln(pkg:"intel-microcode", ver:"3.20201110.0ubuntu0.20.10.2", rls:"UBUNTU20.10"))) {
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