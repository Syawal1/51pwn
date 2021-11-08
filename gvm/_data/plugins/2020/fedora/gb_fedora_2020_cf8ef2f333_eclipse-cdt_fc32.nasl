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
  script_oid("1.3.6.1.4.1.25623.1.0.878252");
  script_version("2020-09-02T06:38:34+0000");
  script_cve_id("CVE-2019-17566", "CVE-2019-17638");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-09-02 06:38:34 +0000 (Wed, 02 Sep 2020)");
  script_tag(name:"creation_date", value:"2020-09-02 11:51:01 +0530 (Wed, 02 Sep 2020)");
  script_name("Fedora: Security Advisory for eclipse-cdt (FEDORA-2020-cf8ef2f333)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC32");

  script_xref(name:"FEDORA", value:"2020-cf8ef2f333");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/XE6OXX2AYSWZGK75IGU2LQS7LBEKKDFC");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'eclipse-cdt'
  package(s) announced via the FEDORA-2020-cf8ef2f333 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Eclipse features and plugins that are useful for C and C++ development.");

  script_tag(name:"affected", value:"'eclipse-cdt' package(s) on Fedora 32.");

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

if(release == "FC32") {

  if(!isnull(res = isrpmvuln(pkg:"eclipse-cdt", rpm:"eclipse-cdt~9.11.1~8.fc32", rls:"FC32"))) {
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