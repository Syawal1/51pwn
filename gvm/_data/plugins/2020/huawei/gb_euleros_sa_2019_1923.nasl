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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2019.1923");
  script_version("2020-03-03T09:12:51+0000");
  script_cve_id("CVE-2018-6954", "CVE-2019-3842");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2020-03-03 09:12:51 +0000 (Tue, 03 Mar 2020)");
  script_tag(name:"creation_date", value:"2020-01-23 12:26:54 +0000 (Thu, 23 Jan 2020)");
  script_name("Huawei EulerOS: Security Advisory for systemd (EulerOS-SA-2019-1923)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRTARM64-3\.0\.2\.0");

  script_xref(name:"EulerOS-SA", value:"2019-1923");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1923");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS
  'systemd' package(s) announced via the EulerOS-SA-2019-1923 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that pam_systemd does not properly sanitize the environment before using the XDG_SEAT variable. It is possible for an attacker, in some particular configurations, to set a XDG_SEAT environment variable which allows for commands to be checked against polkit policies using the 'allow_active' element rather than 'allow_any'.(CVE-2019-3842)

It has been discovered that systemd-tmpfiles mishandles symbolic links present in non-terminal path components. In some configurations a local user could use this vulnerability to get access to arbitrary files when the systemd-tmpfiles command is run.(CVE-2018-6954)");

  script_tag(name:"affected", value:"'systemd' package(s) on Huawei EulerOS Virtualization for ARM 64 3.0.2.0.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "EULEROSVIRTARM64-3.0.2.0") {

  if(!isnull(res = isrpmvuln(pkg:"libgudev1", rpm:"libgudev1~219~62.5.h107", rls:"EULEROSVIRTARM64-3.0.2.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd", rpm:"systemd~219~62.5.h107", rls:"EULEROSVIRTARM64-3.0.2.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-libs", rpm:"systemd-libs~219~62.5.h107", rls:"EULEROSVIRTARM64-3.0.2.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-networkd", rpm:"systemd-networkd~219~62.5.h107", rls:"EULEROSVIRTARM64-3.0.2.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-python", rpm:"systemd-python~219~62.5.h107", rls:"EULEROSVIRTARM64-3.0.2.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-resolved", rpm:"systemd-resolved~219~62.5.h107", rls:"EULEROSVIRTARM64-3.0.2.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-sysv", rpm:"systemd-sysv~219~62.5.h107", rls:"EULEROSVIRTARM64-3.0.2.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-udev-compat", rpm:"systemd-udev-compat~219~62.5.h107", rls:"EULEROSVIRTARM64-3.0.2.0"))) {
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