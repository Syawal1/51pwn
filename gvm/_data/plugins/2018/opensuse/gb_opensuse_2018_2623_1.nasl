# Copyright (C) 2018 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.851880");
  script_version("2020-11-12T08:48:24+0000");
  script_tag(name:"last_modification", value:"2020-11-12 08:48:24 +0000 (Thu, 12 Nov 2020)");
  script_tag(name:"creation_date", value:"2018-09-06 07:12:51 +0200 (Thu, 06 Sep 2018)");
  script_cve_id("CVE-2018-14779", "CVE-2018-14780");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("openSUSE: Security Advisory for yubico-piv-tool (openSUSE-SU-2018:2623-1)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'yubico-piv-tool'
  package(s) announced via the referenced advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for yubico-piv-tool fixes the following issues:

  Security issues fixed:

  - CVE-2018-14779: Fixed a buffer overflow and an out of bounds memory
  read in ykpiv_transfer_data(), which could be triggered by a malicious
  token. (boo#1104809, YSA-2018-03)

  - CVE-2018-14780: Fixed a buffer overflow and an out of bounds memory
  read in _ykpiv_fetch_object(), which could be triggered by a malicious
  token. (boo#1104811, YSA-2018-03)

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2018-969=1");

  script_tag(name:"affected", value:"yubico-piv-tool on openSUSE Leap 42.3");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_xref(name:"openSUSE-SU", value:"2018:2623-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-security-announce/2018-09/msg00010.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap42\.3");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "openSUSELeap42.3") {
  if(!isnull(res = isrpmvuln(pkg:"libykpiv-devel", rpm:"libykpiv-devel~0.1.6~7.3.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libykpiv1", rpm:"libykpiv1~0.1.6~7.3.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libykpiv1-debuginfo", rpm:"libykpiv1-debuginfo~0.1.6~7.3.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"yubico-piv-tool", rpm:"yubico-piv-tool~0.1.6~7.3.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"yubico-piv-tool-debuginfo", rpm:"yubico-piv-tool-debuginfo~0.1.6~7.3.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"yubico-piv-tool-debugsource", rpm:"yubico-piv-tool-debugsource~0.1.6~7.3.1", rls:"openSUSELeap42.3"))) {
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
