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
  script_oid("1.3.6.1.4.1.25623.1.0.878515");
  script_version("2020-10-29T06:27:27+0000");
  script_cve_id("CVE-2020-11979");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2020-10-29 06:27:27 +0000 (Thu, 29 Oct 2020)");
  script_tag(name:"creation_date", value:"2020-10-25 04:11:35 +0000 (Sun, 25 Oct 2020)");
  script_name("Fedora: Security Advisory for ant (FEDORA-2020-3ce0f55bc5)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC31");

  script_xref(name:"FEDORA", value:"2020-3ce0f55bc5");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/DYBRN5C2RW7JRY75IB7Q7ZVKZCHWAQWS");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ant'
  package(s) announced via the FEDORA-2020-3ce0f55bc5 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Apache Ant is a Java library and command-line tool whose mission is to
drive processes described in build files as targets and extension
points dependent upon each other.  The main known usage of Ant is the
build of Java applications.  Ant supplies a number of built-in tasks
allowing to compile, assemble, test and run Java applications.  Ant
can also be used effectively to build non Java applications, for
instance C or C++ applications.  More generally, Ant can be used to
pilot any type of process which can be described in terms of targets
and tasks.");

  script_tag(name:"affected", value:"'ant' package(s) on Fedora 31.");

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

if(release == "FC31") {

  if(!isnull(res = isrpmvuln(pkg:"ant", rpm:"ant~1.10.9~1.fc31", rls:"FC31"))) {
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