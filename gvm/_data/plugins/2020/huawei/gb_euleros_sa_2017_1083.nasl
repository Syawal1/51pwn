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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2017.1083");
  script_version("2020-01-23T10:48:33+0000");
  script_cve_id("CVE-2017-2616");
  script_tag(name:"cvss_base", value:"4.7");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2020-01-23 10:48:33 +0000 (Thu, 23 Jan 2020)");
  script_tag(name:"creation_date", value:"2020-01-23 10:48:33 +0000 (Thu, 23 Jan 2020)");
  script_name("Huawei EulerOS: Security Advisory for util-linux (EulerOS-SA-2017-1083)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS-2\.0SP1");

  script_xref(name:"EulerOS-SA", value:"2017-1083");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2017-1083");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS
  'util-linux' package(s) announced via the EulerOS-SA-2017-1083 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A race condition was found in the way su handled the management of child processes. A local authenticated attacker could use this flaw to kill other processes with root privileges under specific conditions. (CVE-2017-2616)");

  script_tag(name:"affected", value:"'util-linux' package(s) on Huawei EulerOS V2.0SP1.");

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

if(release == "EULEROS-2.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"libblkid", rpm:"libblkid~2.23.2~33.0.1.2", rls:"EULEROS-2.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libblkid-devel", rpm:"libblkid-devel~2.23.2~33.0.1.2", rls:"EULEROS-2.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmount", rpm:"libmount~2.23.2~33.0.1.2", rls:"EULEROS-2.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libuuid", rpm:"libuuid~2.23.2~33.0.1.2", rls:"EULEROS-2.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libuuid-devel", rpm:"libuuid-devel~2.23.2~33.0.1.2", rls:"EULEROS-2.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"util-linux", rpm:"util-linux~2.23.2~33.0.1.2", rls:"EULEROS-2.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uuidd", rpm:"uuidd~2.23.2~33.0.1.2", rls:"EULEROS-2.0SP1"))) {
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