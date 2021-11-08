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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2019.2421");
  script_version("2020-01-23T12:54:21+0000");
  script_cve_id("CVE-2017-10971", "CVE-2017-10972", "CVE-2017-12176", "CVE-2017-12177", "CVE-2017-12178", "CVE-2017-12179", "CVE-2017-12180", "CVE-2017-12181", "CVE-2017-12182", "CVE-2017-12183", "CVE-2017-12184", "CVE-2017-12185", "CVE-2017-12186", "CVE-2017-12187", "CVE-2017-13721", "CVE-2017-2624", "CVE-2018-14665");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-01-23 12:54:21 +0000 (Thu, 23 Jan 2020)");
  script_tag(name:"creation_date", value:"2020-01-23 12:54:21 +0000 (Thu, 23 Jan 2020)");
  script_name("Huawei EulerOS: Security Advisory for xorg-x11-server (EulerOS-SA-2019-2421)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS-2\.0SP2");

  script_xref(name:"EulerOS-SA", value:"2019-2421");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-2421");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS
  'xorg-x11-server' package(s) announced via the EulerOS-SA-2019-2421 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"xorg-x11-server before 1.19.5 was vulnerable to integer overflow in ProcDbeGetVisualInfo function allowing malicious X client to cause X server to crash or possibly execute arbitrary code.(CVE-2017-12177)

xorg-x11-server before 1.19.5 had wrong extra length check in ProcXIChangeHierarchy function allowing malicious X client to cause X server to crash or possibly execute arbitrary code.(CVE-2017-12178)

xorg-x11-server before 1.19.5 was vulnerable to integer overflow in (S)ProcXIBarrierReleasePointer functions allowing malicious X client to cause X server to crash or possibly execute arbitrary code.(CVE-2017-12179)

xorg-x11-server before 1.19.5 was missing length validation in XFree86 VidModeExtension allowing malicious X client to cause X server to crash or possibly execute arbitrary code.(CVE-2017-12180)

xorg-x11-server before 1.19.5 was missing length validation in XFree86 DGA extension allowing malicious X client to cause X server to crash or possibly execute arbitrary code.(CVE-2017-12181)

xorg-x11-server before 1.19.5 was missing length validation in XFree86 DRI extension allowing malicious X client to cause X server to crash or possibly execute arbitrary code.(CVE-2017-12182)

xorg-x11-server before 1.19.5 was missing length validation in XFIXES extension allowing malicious X client to cause X server to crash or possibly execute arbitrary code.(CVE-2017-12183)

xorg-x11-server before 1.19.5 was missing length validation in XINERAMA extension allowing malicious X client to cause X server to crash or possibly execute arbitrary code.(CVE-2017-12184)

xorg-x11-server before 1.19.5 was missing length validation in MIT-SCREEN-SAVER extension allowing malicious X client to cause X server to crash or possibly execute arbitrary code.(CVE-2017-12185)

xorg-x11-server before 1.19.5 was missing length validation in X-Resource extension allowing malicious X client to cause X server to crash or possibly execute arbitrary code.(CVE-2017-12186)

xorg-x11-server before 1.19.5 was missing length validation in RENDER extension allowing malicious X client to cause X server to crash or possibly execute arbitrary code.(CVE-2017-12187)

In X.Org Server (aka xserver and xorg-server) before 1.19.4, an attacker authenticated to an X server with the X shared memory extension enabled can cause aborts of the X server or replace shared memory segments of other X clients in the same session.(CVE-2017-13721)

It was found that xorg-x11-server before 1.19.0 including uses memcmp() to check the received MIT cookie against a series of valid cookies. If the cookie is correct, it is allowed to attach to the  ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'xorg-x11-server' package(s) on Huawei EulerOS V2.0SP2.");

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

if(release == "EULEROS-2.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"xorg-x11-server-Xephyr", rpm:"xorg-x11-server-Xephyr~1.17.2~10.h3", rls:"EULEROS-2.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xorg-x11-server-Xorg", rpm:"xorg-x11-server-Xorg~1.17.2~10.h3", rls:"EULEROS-2.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xorg-x11-server-common", rpm:"xorg-x11-server-common~1.17.2~10.h3", rls:"EULEROS-2.0SP2"))) {
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