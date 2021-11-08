# Copyright (C) 2018 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.852189");
  script_version("2020-04-02T11:36:28+0000");
  script_tag(name:"deprecated", value:TRUE);
  script_cve_id("CVE-2018-19519");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2020-04-02 11:36:28 +0000 (Thu, 02 Apr 2020)");
  script_tag(name:"creation_date", value:"2018-12-18 07:41:32 +0100 (Tue, 18 Dec 2018)");
  script_name("openSUSE: Security Advisory for tcpdump (openSUSE-SU-2018:4144-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");

  script_xref(name:"openSUSE-SU", value:"2018:4144-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-security-announce/2018-12/msg00042.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tcpdump'
  package(s) announced via the openSUSE-SU-2018:4144-1 advisory.

  This NVT has been replaced by OID: 1.3.6.1.4.1.25623.1.0.814580");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for tcpdump fixes the following issues:

  Security issues fixed:

  - CVE-2018-19519: Fixed a stack-based buffer over-read in the print_prefix
  function (bsc#1117267)

  This update was imported from the SUSE:SLE-15:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2018-1559=1");

  script_tag(name:"affected", value:"tcpdump on openSUSE Leap 15.0.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

exit(66); ## This NVT is deprecated as addressed in OID: 1.3.6.1.4.1.25623.1.0.814580
