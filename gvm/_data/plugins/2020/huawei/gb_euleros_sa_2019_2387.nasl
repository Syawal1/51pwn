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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2019.2387");
  script_version("2020-02-05T08:56:28+0000");
  script_cve_id("CVE-2016-2365", "CVE-2016-2366", "CVE-2016-2367", "CVE-2016-2368", "CVE-2016-2369", "CVE-2016-2370", "CVE-2016-2371", "CVE-2016-2373", "CVE-2016-2374", "CVE-2016-2375", "CVE-2016-2376", "CVE-2016-2377", "CVE-2016-2378", "CVE-2016-2380", "CVE-2016-4323");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-02-05 08:56:28 +0000 (Wed, 05 Feb 2020)");
  script_tag(name:"creation_date", value:"2020-01-23 12:52:44 +0000 (Thu, 23 Jan 2020)");
  script_name("Huawei EulerOS: Security Advisory for pidgin (EulerOS-SA-2019-2387)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS-2\.0SP2");

  script_xref(name:"EulerOS-SA", value:"2019-2387");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-2387");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS
  'pidgin' package(s) announced via the EulerOS-SA-2019-2387 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An information leak exists in the handling of the MXIT protocol in Pidgin. Specially crafted MXIT data sent via the server could potentially result in an out-of-bounds read. A malicious user, server, or man-in-the-middle can send an invalid size for an avatar which will trigger an out-of-bounds read vulnerability. This could result in a denial of service or copy data from memory to the file, resulting in an information leak if the avatar is sent to another user.(CVE-2016-2367)

A denial of service vulnerability exists in the handling of the MXIT protocol in Pidgin. Specially crafted MXIT data sent from the server could potentially result in an out-of-bounds read. A malicious server or man-in-the-middle attacker can send invalid data to trigger this vulnerability.(CVE-2016-2370)

A denial of service vulnerability exists in the handling of the MXIT protocol in Pidgin. Specially crafted MXIT data sent via the server could potentially result in a null pointer dereference. A malicious server or an attacker who intercepts the network traffic can send invalid data to trigger this vulnerability and cause a crash.(CVE-2016-2365)

A buffer overflow vulnerability exists in the handling of the MXIT protocol Pidgin. Specially crafted data sent via the server could potentially result in a buffer overflow, potentially resulting in memory corruption. A malicious server or an unfiltered malicious user can send negative length values to trigger this vulnerability.(CVE-2016-2378)

A denial of service vulnerability exists in the handling of the MXIT protocol in Pidgin. Specially crafted MXIT data sent via the server could potentially result in an out-of-bounds read. A malicious server or an attacker who intercepts the network traffic can send invalid data to trigger this vulnerability and cause a crash.(CVE-2016-2366)

Multiple memory corruption vulnerabilities exist in the handling of the MXIT protocol in Pidgin. Specially crafted MXIT data sent via the server could result in multiple buffer overflows, potentially resulting in code execution or memory disclosure.(CVE-2016-2368)

A NULL pointer dereference vulnerability exists in the handling of the MXIT protocol in Pidgin. Specially crafted MXIT data sent via the server could potentially result in a denial of service vulnerability. A malicious server can send a packet starting with a NULL byte triggering the vulnerability.(CVE-2016-2369)

An out-of-bounds write vulnerability exists in the handling of the MXIT protocol in Pidgin. Specially crafted MXIT data sent via the server could cause memory corruption resulting in code execution.(CVE-2016-2371)

A denial ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'pidgin' package(s) on Huawei EulerOS V2.0SP2.");

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

  if(!isnull(res = isrpmvuln(pkg:"libpurple", rpm:"libpurple~2.10.11~5.h3", rls:"EULEROS-2.0SP2"))) {
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
