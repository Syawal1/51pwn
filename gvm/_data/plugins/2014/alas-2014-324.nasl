# Copyright (C) 2015 Eero Volotinen
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) of their respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.120213");
  script_version("2020-03-13T13:19:50+0000");
  script_tag(name:"creation_date", value:"2015-09-08 13:20:33 +0200 (Tue, 08 Sep 2015)");
  script_tag(name:"last_modification", value:"2020-03-13 13:19:50 +0000 (Fri, 13 Mar 2020)");
  script_name("Amazon Linux: Security Advisory (ALAS-2014-324)");
  script_tag(name:"insight", value:"The yaml_parser_scan_tag_uri function in scanner.c in LibYAML before 0.1.5 performs an incorrect cast, which allows remote attackers to cause a denial of service (application crash) and possibly execute arbitrary code via crafted tags in a YAML document, which triggers a heap-based buffer overflow.Heap-based buffer overflow in the yaml_parser_scan_uri_escapes function in LibYAML before 0.1.6 allows context-dependent attackers to execute arbitrary code via a long sequence of percent-encoded characters in a URI in a YAML file.");
  script_tag(name:"solution", value:"Run yum update perl-YAML-LibYAML to update your system.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://alas.aws.amazon.com/ALAS-2014-324.html");
  script_cve_id("CVE-2013-6393", "CVE-2014-2525");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/amazon_linux", "ssh/login/release");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"summary", value:"The remote host is missing an update announced via the referenced Security Advisory.");
  script_copyright("Copyright (C) 2015 Eero Volotinen");
  script_family("Amazon Linux Local Security Checks");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "AMAZON") {
  if(!isnull(res = isrpmvuln(pkg:"perl-YAML-LibYAML-debuginfo", rpm:"perl-YAML-LibYAML-debuginfo~0.41~4.9.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-YAML-LibYAML", rpm:"perl-YAML-LibYAML~0.41~4.9.amzn1", rls:"AMAZON"))) {
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
