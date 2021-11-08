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
  script_oid("1.3.6.1.4.1.25623.1.0.851704");
  script_version("2020-01-31T08:23:39+0000");
  script_tag(name:"last_modification", value:"2020-01-31 08:23:39 +0000 (Fri, 31 Jan 2020)");
  script_tag(name:"creation_date", value:"2018-02-17 08:35:16 +0100 (Sat, 17 Feb 2018)");
  script_cve_id("CVE-2017-15595", "CVE-2017-17563", "CVE-2017-17564", "CVE-2017-17565",
                "CVE-2017-17566", "CVE-2017-18030", "CVE-2017-5715", "CVE-2017-5753",
                "CVE-2017-5754", "CVE-2018-5683");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("openSUSE: Security Advisory for xen (openSUSE-SU-2018:0459-1)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xen'
  package(s) announced via the referenced advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for xen fixes several issues.

  These security issues were fixed:

  - CVE-2017-5753, CVE-2017-5715, CVE-2017-5754: Prevent information leaks
  via side effects of speculative execution, aka 'Spectre' and 'Meltdown'
  attacks (bsc#1074562, bsc#1068032)

  - CVE-2017-15595: x86 PV guest OS users were able to cause a DoS
  (unbounded recursion, stack consumption, and hypervisor crash) or
  possibly gain privileges via crafted page-table stacking (bsc#1061081)

  - CVE-2017-17566: Prevent PV guest OS users to cause a denial of service
  (host OS crash) or gain host OS privileges in shadow mode by mapping a
  certain auxiliary page (bsc#1070158).

  - CVE-2017-17563: Prevent guest OS users to cause a denial of service
  (host OS crash) or gain host OS privileges by leveraging an incorrect
  mask for reference-count overflow checking in shadow mode (bsc#1070159).

  - CVE-2017-17564: Prevent guest OS users to cause a denial of service
  (host OS crash) or gain host OS privileges by leveraging incorrect error
  handling for reference counting in shadow mode (bsc#1070160).

  - CVE-2017-17565: Prevent PV guest OS users to cause a denial of service
  (host OS crash) if shadow mode and log-dirty mode are in place, because
  of an incorrect assertion related to M2P (bsc#1070163).

  - CVE-2018-5683: The vga_draw_text function allowed local OS guest
  privileged users to cause a denial of service (out-of-bounds read and
  QEMU process crash) by leveraging improper memory address validation
  (bsc#1076116).

  - CVE-2017-18030: The cirrus_invalidate_region function allowed local OS
  guest privileged users to cause a denial of service (out-of-bounds array
  access and QEMU process crash) via vectors related to negative pitch
  (bsc#1076180).

  These non-security issues were fixed:

  - bsc#1067317: pass cache=writebackunsafedirectsync to qemu depending on
  the libxl disk settings

  - bsc#1051729: Prevent invalid symlinks after install of SLES 12 SP2

  - bsc#1035442: Increased the value of LIBXL_DESTROY_TIMEOUT from 10 to 100
  seconds. If many domUs shutdown in parallel the backends couldn't keep up

  - bsc#1027519: Added several upstream patches

  This update was imported from the SUSE:SLE-12-SP3:Update update project.");

  script_tag(name:"affected", value:"xen on openSUSE Leap 42.3");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_xref(name:"openSUSE-SU", value:"2018:0459-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-security-announce/2018-02/msg00033.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap42\.3");
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
  if(!isnull(res = isrpmvuln(pkg:"xen", rpm:"xen~4.9.1_08~16.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-debugsource", rpm:"xen-debugsource~4.9.1_08~16.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-devel", rpm:"xen-devel~4.9.1_08~16.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-doc-html", rpm:"xen-doc-html~4.9.1_08~16.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs", rpm:"xen-libs~4.9.1_08~16.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs-debuginfo", rpm:"xen-libs-debuginfo~4.9.1_08~16.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools", rpm:"xen-tools~4.9.1_08~16.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools-debuginfo", rpm:"xen-tools-debuginfo~4.9.1_08~16.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools-domU", rpm:"xen-tools-domU~4.9.1_08~16.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools-domU-debuginfo", rpm:"xen-tools-domU-debuginfo~4.9.1_08~16.1", rls:"openSUSELeap42.3"))) {
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
