###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_1641_1.nasl 14132 2019-03-13 09:25:59Z cfischer $
#
# Ubuntu Update for keystone USN-1641-1
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-1641-1/");
  script_oid("1.3.6.1.4.1.25623.1.0.841227");
  script_version("$Revision: 14132 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2012-11-29 09:40:15 +0530 (Thu, 29 Nov 2012)");
  script_cve_id("CVE-2012-5571", "CVE-2012-3426", "CVE-2012-5563");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:N");
  script_xref(name:"USN", value:"1641-1");
  script_name("Ubuntu Update for keystone USN-1641-1");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(12\.04 LTS|12\.10)");
  script_tag(name:"summary", value:"Ubuntu Update for Linux kernel vulnerabilities USN-1641-1");
  script_tag(name:"affected", value:"keystone on Ubuntu 12.10,
  Ubuntu 12.04 LTS");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"Vijaya Erukala discovered that Keystone did not properly invalidate
  EC2-style credentials such that if credentials were removed from a tenant,
  an authenticated and authorized user using those credentials may still be
  allowed access beyond the account owner's expectations. (CVE-2012-5571)

  It was discovered that Keystone did not properly implement token
  expiration. A remote attacker could use this to continue to access an
  account that is disabled or has a changed password. This issue was
  previously fixed as CVE-2012-3426 but was reintroduced in Ubuntu 12.10.
  (CVE-2012-5563)");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "UBUNTU12.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"python-keystone", ver:"2012.1+stable~20120824-a16a0ab9-0ubuntu2.3", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU12.10")
{

  if ((res = isdpkgvuln(pkg:"python-keystone", ver:"2012.2-0ubuntu1.2", rls:"UBUNTU12.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
