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
  script_oid("1.3.6.1.4.1.25623.1.0.891437");
  script_version("2020-01-29T08:22:52+0000");
  script_cve_id("CVE-2018-10995", "CVE-2018-7033");
  script_name("Debian LTS: Security Advisory for slurm-llnl (DLA-1437-1)");
  script_tag(name:"last_modification", value:"2020-01-29 08:22:52 +0000 (Wed, 29 Jan 2020)");
  script_tag(name:"creation_date", value:"2018-07-23 00:00:00 +0200 (Mon, 23 Jul 2018)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2018/07/msg00029.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_tag(name:"affected", value:"slurm-llnl on Debian Linux");

  script_tag(name:"solution", value:"For Debian 8 'Jessie', these problems have been fixed in version
14.03.9-5+deb8u3.

We recommend that you upgrade your slurm-llnl packages.");

  script_tag(name:"summary", value:"CVE-2018-7033
Fix for issue in accounting_storage/mysql plugin by always
escaping strings within the slurmdbd.

CVE-2018-10995
Fix for mishandling of user names (aka user_name fields) and
group ids (aka gid fields).");

  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"libpam-slurm", ver:"14.03.9-5+deb8u3", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libpmi0", ver:"14.03.9-5+deb8u3", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libpmi0-dev", ver:"14.03.9-5+deb8u3", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libslurm-dev", ver:"14.03.9-5+deb8u3", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libslurm-perl", ver:"14.03.9-5+deb8u3", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libslurm27", ver:"14.03.9-5+deb8u3", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libslurmdb-dev", ver:"14.03.9-5+deb8u3", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libslurmdb-perl", ver:"14.03.9-5+deb8u3", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libslurmdb27", ver:"14.03.9-5+deb8u3", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"slurm-client", ver:"14.03.9-5+deb8u3", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"slurm-llnl", ver:"14.03.9-5+deb8u3", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"slurm-llnl-slurmdbd", ver:"14.03.9-5+deb8u3", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"slurm-wlm", ver:"14.03.9-5+deb8u3", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"slurm-wlm-basic-plugins", ver:"14.03.9-5+deb8u3", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"slurm-wlm-basic-plugins-dev", ver:"14.03.9-5+deb8u3", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"slurm-wlm-doc", ver:"14.03.9-5+deb8u3", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"slurm-wlm-torque", ver:"14.03.9-5+deb8u3", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"slurmctld", ver:"14.03.9-5+deb8u3", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"slurmd", ver:"14.03.9-5+deb8u3", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"slurmdbd", ver:"14.03.9-5+deb8u3", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"sview", ver:"14.03.9-5+deb8u3", rls:"DEB8"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}
