# Copyright (C) 2020 Greenbone Networks GmbH
# Some text descriptions might be excerpted from the referenced
# advisories, and are Copyright (C) by the respective right holder(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.877368");
  script_version("2020-04-28T06:22:45+0000");
  script_cve_id("CVE-2019-19746", "CVE-2019-19797");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2020-04-28 06:22:45 +0000 (Tue, 28 Apr 2020)");
  script_tag(name:"creation_date", value:"2020-01-27 09:24:01 +0000 (Mon, 27 Jan 2020)");
  script_name("Fedora: Security Advisory for transfig (FEDORA-2020-6a2824178e)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC30");

  script_xref(name:"FEDORA", value:"2020-6a2824178e");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/7DHT2H26YTJQC3SPYPFUPZZJG26MWGTL");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'transfig'
  package(s) announced via the FEDORA-2020-6a2824178e advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The transfig utility creates a makefile which translates FIG (created
by xfig) or PIC figures into a specified LaTeX graphics language (for
example, PostScript(TM)).  Transfig is used to create TeX documents
which are portable (i.e., they can be printed in a wide variety of
environments).

Install transfig if you need a utility for translating FIG or PIC
figures into certain graphics languages.");

  script_tag(name:"affected", value:"'transfig' package(s) on Fedora 30.");

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

if(release == "FC30") {

  if(!isnull(res = isrpmvuln(pkg:"transfig", rpm:"transfig~3.2.7b~1.fc30", rls:"FC30"))) {
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