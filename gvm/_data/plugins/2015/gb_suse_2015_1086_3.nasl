# Copyright (C) 2015 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.851032");
  script_version("2020-01-31T07:58:03+0000");
  script_tag(name:"last_modification", value:"2020-01-31 07:58:03 +0000 (Fri, 31 Jan 2020)");
  script_tag(name:"creation_date", value:"2015-10-16 18:22:11 +0200 (Fri, 16 Oct 2015)");
  script_cve_id("CVE-2015-0138", "CVE-2015-0192", "CVE-2015-0204", "CVE-2015-0458", "CVE-2015-0459", "CVE-2015-0469", "CVE-2015-0477", "CVE-2015-0478", "CVE-2015-0480", "CVE-2015-0488", "CVE-2015-0491", "CVE-2015-1914", "CVE-2015-2808");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("SUSE: Security Advisory for Java (SUSE-SU-2015:1086-3)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Java'
  package(s) announced via the referenced advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"IBM Java 1.7.0 was updated to SR9 fixing security issues and bugs.

  Tabulated information can be found on the linked alert.

  CVE-2015-0192 CVE-2015-2808 CVE-2015-1914 CVE-2015-0138 CVE-2015-0491
  CVE-2015-0458 CVE-2015-0459 CVE-2015-0469 CVE-2015-0480 CVE-2015-0488
  CVE-2015-0478 CVE-2015-0477 CVE-2015-0204");

  script_tag(name:"affected", value:"Java on SUSE Linux Enterprise Server 11 SP2 LTSS");

  script_tag(name:"solution", value:"Please install the updated package(s).");
  script_xref(name:"SUSE-SU", value:"2015:1086-3");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=SLES11\.0SP2");

  script_xref(name:"URL", value:"http://www.ibm.com/developerworks/java/jdk/alerts/#IBM_Security_Update_May_2015");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "SLES11.0SP2") {
  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-ibm", rpm:"java-1_7_0-ibm~1.7.0_sr9.0~0.7.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-ibm-devel", rpm:"java-1_7_0-ibm-devel~1.7.0_sr9.0~0.7.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-ibm-jdbc", rpm:"java-1_7_0-ibm-jdbc~1.7.0_sr9.0~0.7.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-ibm-alsa", rpm:"java-1_7_0-ibm-alsa~1.7.0_sr9.0~0.7.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-ibm-plugin", rpm:"java-1_7_0-ibm-plugin~1.7.0_sr9.0~0.7.1", rls:"SLES11.0SP2"))) {
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
