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
  script_oid("1.3.6.1.4.1.25623.1.0.120584");
  script_version("2020-03-13T13:19:50+0000");
  script_tag(name:"creation_date", value:"2015-09-08 13:30:06 +0200 (Tue, 08 Sep 2015)");
  script_tag(name:"last_modification", value:"2020-03-13 13:19:50 +0000 (Fri, 13 Mar 2020)");
  script_name("Amazon Linux: Security Advisory (ALAS-2012-62)");
  script_tag(name:"insight", value:"A NULL pointer dereference flaw was found in the way OpenSSL parsed Secure/Multipurpose Internet Mail Extensions (S/MIME) messages. An attacker could use this flaw to crash an application that uses OpenSSL to decrypt or verify S/MIME messages. (CVE-2012-1165 )A flaw was found in the PKCS#7 and Cryptographic Message Syntax (CMS) implementations in OpenSSL. An attacker could possibly use this flaw to perform a Bleichenbacher attack to decrypt an encrypted CMS, PKCS#7, or S/MIME message by sending a large number of chosen ciphertext messages to a service using OpenSSL and measuring error response times. (CVE-2012-0884 )");
  script_tag(name:"solution", value:"Run yum update openssl to update your system.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://alas.aws.amazon.com/ALAS-2012-62.html");
  script_cve_id("CVE-2012-1165", "CVE-2012-0884");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
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
  if(!isnull(res = isrpmvuln(pkg:"openssl-devel", rpm:"openssl-devel~1.0.0g~2.39.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-static", rpm:"openssl-static~1.0.0g~2.39.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-perl", rpm:"openssl-perl~1.0.0g~2.39.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-debuginfo", rpm:"openssl-debuginfo~1.0.0g~2.39.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl", rpm:"openssl~1.0.0g~2.39.amzn1", rls:"AMAZON"))) {
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
