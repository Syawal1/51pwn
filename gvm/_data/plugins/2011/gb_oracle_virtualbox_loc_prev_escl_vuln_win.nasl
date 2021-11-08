###############################################################################
# OpenVAS Vulnerability Test
#
# Oracle VM VirtualBox Extensions Local Privilege Escalation Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.801578");
  script_version("2020-04-23T08:43:39+0000");
  script_tag(name:"last_modification", value:"2020-04-23 08:43:39 +0000 (Thu, 23 Apr 2020)");
  script_tag(name:"creation_date", value:"2011-01-27 07:47:27 +0100 (Thu, 27 Jan 2011)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_cve_id("CVE-2010-4414");
  script_bugtraq_id(45876);
  script_name("Oracle VM VirtualBox Extensions Local Privilege Escalation Vulnerability (Windows)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_sun_virtualbox_detect_win.nasl");
  script_mandatory_keys("Oracle/VirtualBox/Win/Ver");

  script_tag(name:"impact", value:"Successful exploitation will let the local users to gain escalated privileges.");

  script_tag(name:"affected", value:"Oracle VirtualBox version 4.0.");

  script_tag(name:"insight", value:"The flaw is caused by an unspecified error related to various extensions,
  which could allow local authenticated attackers to gain elevated privileges.");

  script_tag(name:"summary", value:"This host is installed with Oracle VirtualBox and is local privilege
  escalation Vulnerability vulnerability.");

  script_tag(name:"solution", value:"Apply the referenced patch.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/cpujan2011-194091.html");
  exit(0);
}

include("version_func.inc");

vmVer = get_kb_item("Oracle/VirtualBox/Win/Ver");
if(vmVer)
{
  if(version_is_equal(version:vmVer, test_version:"4.0")){
    report = report_fixed_ver(installed_version:vmVer, vulnerable_range:"Equal to 4.0");
    security_message(port: 0, data: report);
  }
}
