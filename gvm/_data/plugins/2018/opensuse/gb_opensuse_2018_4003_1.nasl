# Copyright (C) 2018 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) of their respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.852159");
  script_version("2020-01-31T08:23:39+0000");
  script_cve_id("CVE-2018-1059");
  script_tag(name:"cvss_base", value:"2.9");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2020-01-31 08:23:39 +0000 (Fri, 31 Jan 2020)");
  script_tag(name:"creation_date", value:"2018-12-10 07:36:34 +0100 (Mon, 10 Dec 2018)");
  script_name("openSUSE: Security Advisory for dpdk (openSUSE-SU-2018:4003-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap42\.3");

  script_xref(name:"openSUSE-SU", value:"2018:4003-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-security-announce/2018-12/msg00003.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'dpdk'
  package(s) announced via the openSUSE-SU-2018:4003-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for dpdk to version 16.11.8
  provides the following security fix:

  - CVE-2018-1059: restrict untrusted guest to misuse virtio to corrupt host
  application (ovs-dpdk) memory which could have lead all VM to lose
  connectivity (bsc#1089638)

  and following non-security fixes:

  - Enable the broadcom chipset family Broadcom NetXtreme II BCM57810
  (bsc#1073363)

  - Fix a latency problem by using cond_resched rather than
  schedule_timeout_interruptible (bsc#1069601)

  - Fix a syntax error affecting csh environment configuration (bsc#1102310)

  - Fixes in net/bnxt:

  * Fix HW Tx checksum offload check

  * Fix incorrect IO address handling in Tx

  * Fix Rx ring count limitation

  * Check access denied for HWRM commands

  * Fix RETA size

  * Fix close operation

  - Fixes in eal/linux:

  * Fix an invalid syntax in interrupts

  * Fix return codes on thread naming failure

  - Fixes in kni:

  * Fix crash with null name

  * Fix build with gcc 8.1

  - Fixes in net/thunderx:

  * Fix build with gcc optimization on

  * Avoid sq door bell write on zero packet

  - net/bonding: Fix MAC address reset

  - vhost: Fix missing increment of log cache count

  This update was imported from the SUSE:SLE-12-SP3:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2018-1484=1");

  script_tag(name:"affected", value:"dpdk on openSUSE Leap 42.3.");

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

if(release == "openSUSELeap42.3") {
  if(!isnull(res = isrpmvuln(pkg:"dpdk", rpm:"dpdk~16.11.8~6.8.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dpdk-debuginfo", rpm:"dpdk-debuginfo~16.11.8~6.8.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dpdk-debugsource", rpm:"dpdk-debugsource~16.11.8~6.8.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dpdk-devel", rpm:"dpdk-devel~16.11.8~6.8.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dpdk-devel-debuginfo", rpm:"dpdk-devel-debuginfo~16.11.8~6.8.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dpdk-examples", rpm:"dpdk-examples~16.11.8~6.8.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dpdk-examples-debuginfo", rpm:"dpdk-examples-debuginfo~16.11.8~6.8.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dpdk-tools", rpm:"dpdk-tools~16.11.8~6.8.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dpdk-kmp-default", rpm:"dpdk-kmp-default~16.11.8_k4.4.162_78~6.8.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dpdk-kmp-default-debuginfo", rpm:"dpdk-kmp-default-debuginfo~16.11.8_k4.4.162_78~6.8.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dpdk-doc", rpm:"dpdk-doc~16.11.8~6.8.1", rls:"openSUSELeap42.3"))) {
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
