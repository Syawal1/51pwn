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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2019.2021");
  script_version("2020-01-23T12:31:09+0000");
  script_cve_id("CVE-2016-4994", "CVE-2018-12713");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-01-23 12:31:09 +0000 (Thu, 23 Jan 2020)");
  script_tag(name:"creation_date", value:"2020-01-23 12:31:09 +0000 (Thu, 23 Jan 2020)");
  script_name("Huawei EulerOS: Security Advisory for gimp (EulerOS-SA-2019-2021)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS-2\.0SP3");

  script_xref(name:"EulerOS-SA", value:"2019-2021");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-2021");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS
  'gimp' package(s) announced via the EulerOS-SA-2019-2021 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple use-after-free vulnerabilities were found in GIMP in the channel and layer properties parsing process when loading XCF files.An attacker could create a specially crafted XCF file which could cause GIMP to crash. (CVE-2016-4994)

GIMP through 2.10.2 makes g_get_tmp_dir calls to establish temporary filenames, which may result in a filename that already exists, as demonstrated by the gimp_write_and_read_file function in app/tests/test-xcf.c. This might be leveraged by attackers to overwrite files or read file content that was intended to be private.(CVE-2018-12713)");

  script_tag(name:"affected", value:"'gimp' package(s) on Huawei EulerOS V2.0SP3.");

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

if(release == "EULEROS-2.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"gimp", rpm:"gimp~2.8.10~3.h9", rls:"EULEROS-2.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gimp-libs", rpm:"gimp-libs~2.8.10~3.h9", rls:"EULEROS-2.0SP3"))) {
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