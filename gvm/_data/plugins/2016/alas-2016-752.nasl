# Copyright (C) 2016 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.120741");
  script_version("2020-03-13T13:19:50+0000");
  script_tag(name:"creation_date", value:"2016-10-26 15:38:27 +0300 (Wed, 26 Oct 2016)");
  script_tag(name:"last_modification", value:"2020-03-13 13:19:50 +0000 (Fri, 13 Mar 2020)");
  script_name("Amazon Linux: Security Advisory (ALAS-2016-752)");
  script_tag(name:"insight", value:"A possible heap overflow was discovered in the EscapeParenthesis() function (CVE-2016-7447 ).Various issues were found in the processing of SVG files in GraphicsMagick (CVE-2016-7446 ).The TIFF reader had a bug pertaining to use of TIFFGetField() when a 'count' value is returned. The bug caused a heap read overflow (due to using strlcpy() to copy a possibly unterminated string) which could allow an untrusted file to crash the software (CVE-2016-7449 ).The Utah RLE reader did not validate that header information was reasonable given the file size and so it could cause huge memory allocations and/or consume huge amounts of CPU, causing a denial of service (CVE-2016-7448 )");
  script_tag(name:"solution", value:"Run yum update GraphicsMagick to update your system.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://alas.aws.amazon.com/ALAS-2016-752.html");
  script_cve_id("CVE-2016-7447", "CVE-2016-7446", "CVE-2016-7449", "CVE-2016-7448");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"qod_type", value:"package");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/amazon_linux", "ssh/login/release");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"summary", value:"The remote host is missing an update announced via the referenced Security Advisory.");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
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
  if(!isnull(res = isrpmvuln(pkg:"GraphicsMagick-c++-devel", rpm:"GraphicsMagick-c++-devel~1.3.25~1.9.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"GraphicsMagick-devel", rpm:"GraphicsMagick-devel~1.3.25~1.9.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"GraphicsMagick", rpm:"GraphicsMagick~1.3.25~1.9.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"GraphicsMagick-c++", rpm:"GraphicsMagick-c++~1.3.25~1.9.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"GraphicsMagick-perl", rpm:"GraphicsMagick-perl~1.3.25~1.9.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"GraphicsMagick-debuginfo", rpm:"GraphicsMagick-debuginfo~1.3.25~1.9.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"GraphicsMagick-doc", rpm:"GraphicsMagick-doc~1.3.25~1.9.amzn1", rls:"AMAZON"))) {
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
