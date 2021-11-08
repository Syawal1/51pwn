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
  script_oid("1.3.6.1.4.1.25623.1.0.878629");
  script_version("2020-11-19T07:38:10+0000");
  script_cve_id("CVE-2017-18926");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-11-19 07:38:10 +0000 (Thu, 19 Nov 2020)");
  script_tag(name:"creation_date", value:"2020-11-19 04:21:01 +0000 (Thu, 19 Nov 2020)");
  script_name("Fedora: Security Advisory for raptor (FEDORA-2020-b15dd44972)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC33");

  script_xref(name:"FEDORA", value:"2020-b15dd44972");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/RD67AVORGQXORPWNYYUHCH6YPPT6CI4O");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'raptor'
  package(s) announced via the FEDORA-2020-b15dd44972 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Raptor is the RDF Parser Toolkit for Redland that provides
a set of standalone RDF parsers, generating triples from RDF/XML
or N-Triples.");

  script_tag(name:"affected", value:"'raptor' package(s) on Fedora 33.");

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

if(release == "FC33") {

  if(!isnull(res = isrpmvuln(pkg:"raptor", rpm:"raptor~1.4.21~33.fc33", rls:"FC33"))) {
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