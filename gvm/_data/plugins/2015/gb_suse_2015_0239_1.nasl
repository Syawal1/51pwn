# Copyright (C) 2015 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.851051");
  script_version("2020-06-03T08:38:58+0000");
  script_tag(name:"last_modification", value:"2020-06-03 08:38:58 +0000 (Wed, 03 Jun 2020)");
  script_tag(name:"creation_date", value:"2015-10-16 18:57:18 +0200 (Fri, 16 Oct 2015)");
  script_cve_id("CVE-2015-0313", "CVE-2015-0314", "CVE-2015-0315", "CVE-2015-0316", "CVE-2015-0317", "CVE-2015-0318", "CVE-2015-0319", "CVE-2015-0320", "CVE-2015-0321", "CVE-2015-0322", "CVE-2015-0323", "CVE-2015-0324", "CVE-2015-0325", "CVE-2015-0326", "CVE-2015-0327", "CVE-2015-0328", "CVE-2015-0329", "CVE-2015-0330");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("SUSE: Security Advisory for flash-player (SUSE-SU-2015:0239-1)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'flash-player'
  package(s) announced via the referenced advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"flash-player was updated to version 11.2.202.442 to fix 18 security issues.

  These security issues were fixed: - Use-after-free vulnerabilities that
  could lead to code execution (CVE-2015-0313, CVE-2015-0315, CVE-2015-0320,
  CVE-2015-0322). - Memory corruption vulnerabilities that could lead to
  code execution (CVE-2015-0314, CVE-2015-0316, CVE-2015-0318,
  CVE-2015-0321, CVE-2015-0329, CVE-2015-0330). - Type confusion
  vulnerabilities that could lead to code execution (CVE-2015-0317,
  CVE-2015-0319). - Heap buffer
  overflow vulnerabilities that could lead to code execution (CVE-2015-0323,
  CVE-2015-0327). - Buffer overflow vulnerability that could lead to code
  execution (CVE-2015-0324). - Null pointer dereference issues
  (CVE-2015-0325, CVE-2015-0326, CVE-2015-0328).");

  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/flash-player/apsb15-04.html");

  script_tag(name:"affected", value:"flash-player, on SUSE Linux Enterprise Desktop 11 SP3");

  script_tag(name:"solution", value:"Please install the updated package(s).");
  script_xref(name:"SUSE-SU", value:"2015:0239-1");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=SLED11\.0SP3");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "SLED11.0SP3") {
  if(!isnull(res = isrpmvuln(pkg:"flash-player", rpm:"flash-player~11.2.202.442~0.3.1", rls:"SLED11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"flash-player-gnome", rpm:"flash-player-gnome~11.2.202.442~0.3.1", rls:"SLED11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"flash-player-kde4", rpm:"flash-player-kde4~11.2.202.442~0.3.1", rls:"SLED11.0SP3"))) {
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
