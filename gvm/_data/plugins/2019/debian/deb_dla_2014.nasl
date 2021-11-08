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
  script_oid("1.3.6.1.4.1.25623.1.0.892014");
  script_version("2020-01-29T08:22:52+0000");
  script_cve_id("CVE-2014-6053", "CVE-2018-7225", "CVE-2019-15681");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-01-29 08:22:52 +0000 (Wed, 29 Jan 2020)");
  script_tag(name:"creation_date", value:"2019-11-30 03:00:09 +0000 (Sat, 30 Nov 2019)");
  script_name("Debian LTS: Security Advisory for vino (DLA-2014-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2019/11/msg00032.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2014-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/945784");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'vino'
  package(s) announced via the DLA-2014-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been identified in the VNC code of vino, a
desktop sharing utility for the GNOME desktop environment.

The vulnerabilities referenced below are issues that have originally been
reported against Debian source package libvncserver. The vino source
package in Debian ships a custom-patched and stripped down variant of
libvncserver, thus some of libvncserver's security fixes required porting
over.

CVE-2014-6053

The rfbProcessClientNormalMessage function in
libvncserver/rfbserver.c in LibVNCServer did not properly handle
attempts to send a large amount of ClientCutText data, which allowed
remote attackers to cause a denial of service (memory consumption or
daemon crash) via a crafted message that was processed by using a
single unchecked malloc.

CVE-2018-7225

An issue was discovered in LibVNCServer.
rfbProcessClientNormalMessage() in rfbserver.c did not sanitize
msg.cct.length, leading to access to uninitialized and potentially
sensitive data or possibly unspecified other impact (e.g., an integer
overflow) via specially crafted VNC packets.

CVE-2019-15681

LibVNC contained a memory leak (CWE-655) in VNC server code, which
allowed an attacker to read stack memory and could be abused for
information disclosure. Combined with another vulnerability, it could
be used to leak stack memory and bypass ASLR. This attack appeared to
be exploitable via network connectivity.");

  script_tag(name:"affected", value:"'vino' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 8 'Jessie', these problems have been fixed in version
3.14.0-2+deb8u1.

We recommend that you upgrade your vino packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"vino", ver:"3.14.0-2+deb8u1", rls:"DEB8"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
