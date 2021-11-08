# Copyright (C) 2019 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.883130");
  script_version("2019-11-15T08:07:38+0000");
  script_cve_id("CVE-2019-14287");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-11-15 08:07:38 +0000 (Fri, 15 Nov 2019)");
  script_tag(name:"creation_date", value:"2019-11-14 03:01:07 +0000 (Thu, 14 Nov 2019)");
  script_name("CentOS Update for sudo CESA-2019:3755 centos6 ");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS6");

  script_xref(name:"CESA", value:"2019:3755");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2019-November/023510.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'sudo'
  package(s) announced via the CESA-2019:3755 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The sudo packages contain the sudo utility which allows system
administrators to provide certain users with the permission to execute
privileged commands, which are used for system management purposes, without
having to log in as root.

Security Fix(es):

  * sudo: Privilege escalation via 'Runas' specification with 'ALL' keyword
(CVE-2019-14287)

For more details about the security issue(s), including the impact, a CVSS
score, acknowledgments, and other related information, refer to the CVE
page(s) listed in the References section.");

  script_tag(name:"affected", value:"'sudo' package(s) on CentOS 6.");

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

if(release == "CentOS6") {

  if(!isnull(res = isrpmvuln(pkg:"sudo", rpm:"sudo~1.8.6p3~29.el6_10.2", rls:"CentOS6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sudo-devel", rpm:"sudo-devel~1.8.6p3~29.el6_10.2", rls:"CentOS6"))) {
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