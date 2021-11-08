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
  script_oid("1.3.6.1.4.1.25623.1.0.878404");
  script_version("2020-10-08T07:56:44+0000");
  script_cve_id("CVE-2020-5267", "CVE-2020-8185", "CVE-2020-15169");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2020-10-08 07:56:44 +0000 (Thu, 08 Oct 2020)");
  script_tag(name:"creation_date", value:"2020-10-05 03:09:29 +0000 (Mon, 05 Oct 2020)");
  script_name("Fedora: Security Advisory for rubygem-actionmailer (FEDORA-2020-4dd34860a3)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC33");

  script_xref(name:"FEDORA", value:"2020-4dd34860a3");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/OCTEWRI3XID5GZOZTXA4X6UOPUSC2UYL");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'rubygem-actionmailer'
  package(s) announced via the FEDORA-2020-4dd34860a3 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Email on Rails. Compose, deliver, and test emails using the familiar
controller/view pattern. First-class support for multipart email and
attachments.");

  script_tag(name:"affected", value:"'rubygem-actionmailer' package(s) on Fedora 33.");

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

  if(!isnull(res = isrpmvuln(pkg:"rubygem-actionmailer", rpm:"rubygem-actionmailer~6.0.3.3~1.fc33", rls:"FC33"))) {
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