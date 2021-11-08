# Copyright (C) 2018 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) of the respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.890958");
  script_version("2020-01-29T08:22:52+0000");
  script_cve_id("CVE-2017-9224", "CVE-2017-9226", "CVE-2017-9227", "CVE-2017-9228", "CVE-2017-9229");
  script_name("Debian LTS: Security Advisory for libonig (DLA-958-1)");
  script_tag(name:"last_modification", value:"2020-01-29 08:22:52 +0000 (Wed, 29 Jan 2020)");
  script_tag(name:"creation_date", value:"2018-01-25 00:00:00 +0100 (Thu, 25 Jan 2018)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2017/05/msg00029.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_tag(name:"affected", value:"libonig on Debian Linux");

  script_tag(name:"solution", value:"For Debian 7 'Wheezy', these problems have been fixed in version
5.9.1-1+deb7u1.

We recommend that you upgrade your libonig packages.");

  script_tag(name:"summary", value:"CVE-2017-9224

An issue was discovered in Oniguruma 6.2.0, as used in Oniguruma-mod in
Ruby through 2.4.1 and mbstring in PHP through 7.1.5. A stack
out-of-bounds read occurs in match_at() during regular expression
searching. A logical error involving order of validation and access in
match_at() could result in an out-of-bounds read from a stack buffer.

CVE-2017-9226

An issue was discovered in Oniguruma 6.2.0, as used in Oniguruma-mod in
Ruby through 2.4.1 and mbstring in PHP through 7.1.5. A heap
out-of-bounds write or read occurs in next_state_val() during regular
expression compilation. Octal numbers larger than 0xff are not handled
correctly in fetch_token() and fetch_token_in_cc(). A malformed regular
expression containing an octal number in the form of '\700' would
produce an invalid code point value larger than 0xff in
next_state_val(), resulting in an out-of-bounds write memory
corruption.

CVE-2017-9227

An issue was discovered in Oniguruma 6.2.0, as used in Oniguruma-mod in
Ruby through 2.4.1 and mbstring in PHP through 7.1.5. A stack
out-of-bounds read occurs in mbc_enc_len() during regular expression
searching. Invalid handling of reg->dmin in forward_search_range()
could result in an invalid pointer dereference, as an out-of-bounds
read from a stack buffer.

CVE-2017-9228

An issue was discovered in Oniguruma 6.2.0, as used in Oniguruma-mod in
Ruby through 2.4.1 and mbstring in PHP through 7.1.5. A heap
out-of-bounds write occurs in bitset_set_range() during regular
expression compilation due to an uninitialized variable from an
incorrect state transition. An incorrect state transition in
parse_char_class() could create an execution path that leaves a
critical local variable uninitialized until it's used as an index,
resulting in an out-of-bounds write memory corruption.

CVE-2017-9229

An issue was discovered in Oniguruma 6.2.0, as used in Oniguruma-mod in
Ruby through 2.4.1 and mbstring in PHP through 7.1.5. A SIGSEGV occurs
in left_adjust_char_head() during regular expression compilation.
Invalid handling of reg->dmax in forward_search_range() could result in
an invalid pointer dereference, normally as an immediate
denial-of-service condition.");

  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"libonig-dev", ver:"5.9.1-1+deb7u1", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libonig2", ver:"5.9.1-1+deb7u1", rls:"DEB7"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libonig2-dbg", ver:"5.9.1-1+deb7u1", rls:"DEB7"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}
