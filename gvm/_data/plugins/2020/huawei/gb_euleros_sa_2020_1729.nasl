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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2020.1729");
  script_version("2020-07-03T06:19:01+0000");
  script_cve_id("CVE-2018-1000807", "CVE-2018-1000808");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-07-03 06:19:01 +0000 (Fri, 03 Jul 2020)");
  script_tag(name:"creation_date", value:"2020-07-03 06:19:01 +0000 (Fri, 03 Jul 2020)");
  script_name("Huawei EulerOS: Security Advisory for pyOpenSSL (EulerOS-SA-2020-1729)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT-3\.0\.6\.0");

  script_xref(name:"EulerOS-SA", value:"2020-1729");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-1729");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS
  'pyOpenSSL' package(s) announced via the EulerOS-SA-2020-1729 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Python Cryptographic Authority pyopenssl version Before 17.5.0 contains a CWE - 401 : Failure to Release Memory Before Removing Last Reference vulnerability in PKCS #12 Store that can result in Denial of service if memory runs low or is exhausted. This attack appear to be exploitable via Depends upon calling application, however it could be as simple as initiating a TLS connection. Anything that would cause the calling application to reload certificates from a PKCS #12 store.. This vulnerability appears to have been fixed in 17.5.0.(CVE-2018-1000808)

Python Cryptographic Authority pyopenssl version prior to version 17.5.0 contains a CWE-416: Use After Free vulnerability in X509 object handling that can result in Use after free can lead to possible denial of service or remote code execution.. This attack appear to be exploitable via Depends on the calling application and if it retains a reference to the memory.. This vulnerability appears to have been fixed in 17.5.0.(CVE-2018-1000807)");

  script_tag(name:"affected", value:"'pyOpenSSL' package(s) on Huawei EulerOS Virtualization 3.0.6.0.");

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

if(release == "EULEROSVIRT-3.0.6.0") {

  if(!isnull(res = isrpmvuln(pkg:"python2-pyOpenSSL", rpm:"python2-pyOpenSSL~16.2.0~4.eulerosv2r7", rls:"EULEROSVIRT-3.0.6.0"))) {
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