###############################################################################
# OpenVAS Vulnerability Test
#
# MS Windows Help and Support Center Remote Code Execution Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Updated By: Antu Sanadi <santu@secpod.com> on 2010-06-16
# Updated CVSS score, Description, References and added the CVE-2010-2265
#
# Updated By: Antu Sanadi <santu@secpod.com> on 2011-05-18
#  -This plugin is invalidated by secpod_ms10-042.nasl
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801358");
  script_version("2020-06-10T11:35:03+0000");
  script_tag(name:"last_modification", value:"2020-06-10 11:35:03 +0000 (Wed, 10 Jun 2020)");
  script_tag(name:"creation_date", value:"2010-06-11 14:27:58 +0200 (Fri, 11 Jun 2010)");
  script_cve_id("CVE-2010-1885", "CVE-2010-2265");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("MS Windows Help and Support Center Remote Code Execution Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Windows");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/59267");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/1417");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/SecurityAdvisories/2010/2219475");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2010/ms10-042");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute
  arbitrary code or compromise a vulnerable system.");

  script_tag(name:"affected", value:"- Microsoft Windows XP Service Pack 2/3

  - Microsoft Windows Server 2003 Service Pack 2");

  script_tag(name:"insight", value:"The flaws are due to:

  - An error in the 'MPC::HTML::UrlUnescapeW()' function within the Help and
  Support Center application (helpctr.exe) that does not properly check the
  return code of 'MPC::HexToNum()' when escaping URLs, which could allow
  attackers to bypass whitelist restrictions and invoke arbitrary help files.

  - An input validation error in the 'GetServerName()' function in the
  'C:\WINDOWS\PCHealth\HelpCtr\System\sysinfo\commonFunc.js' script invoked via
  'ShowServerName()' in 'C:\WINDOWS\PCHealth\HelpCtr\System\sysinfo\sysinfomain.htm',
  which could be exploited by attackers to execute arbitrary scripting code.");

  script_tag(name:"summary", value:"This host is prone to remote code execution vulnerability.

  This VT has been replaced by 'Microsoft Help and Support Center Remote Code Execution Vulnerability (2229593)' (OID: 1.3.6.1.4.1.25623.1.0.902080)");

  script_tag(name:"solution", value:"Vendor has released a patch for the issue. Please see the references
  for more information.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66); # This plugin is invalidated by secpod_ms10-042.nasl
