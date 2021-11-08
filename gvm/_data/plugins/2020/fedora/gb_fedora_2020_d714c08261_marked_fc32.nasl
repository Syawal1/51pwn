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
  script_oid("1.3.6.1.4.1.25623.1.0.877926");
  script_version("2020-06-09T07:30:09+0000");
  script_cve_id("CVE-2015-8854", "CVE-2016-1000013", "CVE-2017-17461", "CVE-2017-1000427");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2020-06-09 07:30:09 +0000 (Tue, 09 Jun 2020)");
  script_tag(name:"creation_date", value:"2020-06-07 03:27:56 +0000 (Sun, 07 Jun 2020)");
  script_name("Fedora: Security Advisory for marked (FEDORA-2020-d714c08261)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC32");

  script_xref(name:"FEDORA", value:"2020-d714c08261");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/BO2RMVVZVV6NFTU46B5RYRK7ZCXYARZS");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'marked'
  package(s) announced via the FEDORA-2020-d714c08261 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Install this for command line tool and man page.

marked is a full-featured markdown compiler that can parse huge chunks of
markdown without having to worry about caching the compiled output or
blocking for an unnecessarily long time.

marked is extremely fast and frequently outperforms similar markdown parsers.
marked is very concise and still implements all markdown features, as well
as GitHub Flavored Markdown features.

marked more or less passes the official markdown test suite in its entirety.
This is important because a surprising number of markdown compilers cannot
pass more than a few tests.");

  script_tag(name:"affected", value:"'marked' package(s) on Fedora 32.");

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

  if(!isnull(res = isrpmvuln(pkg:"marked", rpm:"marked~1.1.0~3.fc32", rls:"FC32"))) {
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