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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2019.1229");
  script_version("2020-10-16T11:47:55+0000");
  script_cve_id("CVE-2018-1092", "CVE-2018-7740");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2020-10-16 11:47:55 +0000 (Fri, 16 Oct 2020)");
  script_tag(name:"creation_date", value:"2020-01-23 11:35:51 +0000 (Thu, 23 Jan 2020)");
  script_name("Huawei EulerOS: Security Advisory for kernel (EulerOS-SA-2019-1229)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT-2\.5\.4");

  script_xref(name:"EulerOS-SA", value:"2019-1229");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1229");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS
  'kernel' package(s) announced via the EulerOS-SA-2019-1229 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The Linux kernel is vulnerable to a NULL pointer dereference in the ext4/mballoc.c:ext4_process_freed_data() function. An attacker could trick a legitimate user or a privileged attacker could exploit this by mounting a crafted ext4 image to cause a kernel panic.(CVE-2018-1092)

The resv_map_release function in mm/hugetlb.c in the Linux kernel, through 4.15.7, allows local users to cause a denial of service (BUG) via a crafted application that makes mmap system calls and has a large pgoff argument to the remap_file_pages system call.(CVE-2018-7740)");

  script_tag(name:"affected", value:"'kernel' package(s) on Huawei EulerOS Virtualization 2.5.4.");

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

if(release == "EULEROSVIRT-2.5.4") {

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~3.10.0~862.14.1.1_54", rls:"EULEROSVIRT-2.5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~3.10.0~862.14.1.1_54", rls:"EULEROSVIRT-2.5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~3.10.0~862.14.1.1_54", rls:"EULEROSVIRT-2.5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~3.10.0~862.14.1.1_54", rls:"EULEROSVIRT-2.5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~3.10.0~862.14.1.1_54", rls:"EULEROSVIRT-2.5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs-devel", rpm:"kernel-tools-libs-devel~3.10.0~862.14.1.1_54", rls:"EULEROSVIRT-2.5.4"))) {
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