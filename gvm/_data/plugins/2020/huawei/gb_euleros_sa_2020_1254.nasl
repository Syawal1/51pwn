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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2020.1254");
  script_version("2020-03-13T07:18:30+0000");
  script_cve_id("CVE-2014-3564");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-03-13 07:18:30 +0000 (Fri, 13 Mar 2020)");
  script_tag(name:"creation_date", value:"2020-03-13 07:18:30 +0000 (Fri, 13 Mar 2020)");
  script_name("Huawei EulerOS: Security Advisory for gpgme (EulerOS-SA-2020-1254)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRTARM64-3\.0\.2\.0");

  script_xref(name:"EulerOS-SA", value:"2020-1254");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-1254");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS
  'gpgme' package(s) announced via the EulerOS-SA-2020-1254 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple heap-based buffer overflows in the status_handler function in (1) engine-gpgsm.c and (2) engine-uiserver.c in GPGME before 1.5.1 allow remote attackers to cause a denial of service (crash) and possibly execute arbitrary code via vectors related to 'different line lengths in a specific order.'(CVE-2014-3564)");

  script_tag(name:"affected", value:"'gpgme' package(s) on Huawei EulerOS Virtualization for ARM 64 3.0.2.0.");

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

  if(!isnull(res = isrpmvuln(pkg:"gpgme", rpm:"gpgme~1.3.2~5.h1", rls:"EULEROSVIRTARM64-3.0.2.0"))) {
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