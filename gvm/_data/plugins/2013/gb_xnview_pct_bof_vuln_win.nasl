###############################################################################
# OpenVAS Vulnerability Test
#
# XnView PCT File Handling Buffer Overflow Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:xnview:xnview";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803740");
  script_version("2020-04-21T11:03:03+0000");
  script_cve_id("CVE-2013-2577");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2020-04-21 11:03:03 +0000 (Tue, 21 Apr 2020)");
  script_tag(name:"creation_date", value:"2013-08-21 12:23:59 +0530 (Wed, 21 Aug 2013)");
  script_name("XnView PCT File Handling Buffer Overflow Vulnerability");
  script_tag(name:"summary", value:"This host is installed XnView and is prone to buffer overflow Vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"solution", value:"Upgrade to XnView 2.04 or later.");
  script_tag(name:"insight", value:"The flaw is due to an improper bounds checking when processing '.PCT' files.");
  script_tag(name:"affected", value:"XnView versions 2.03 and prior for Windows.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary
code on the target machine, by enticing the user of XnView to open a specially
crafted file.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/85919");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/27049");
  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1028817");
  script_xref(name:"URL", value:"http://www.coresecurity.com/advisories/xnview-buffer-overflow-vulnerability");
  script_xref(name:"URL", value:"http://archives.neohapsis.com/archives/bugtraq/2013-07/0153.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("secpod_xnview_detect_win.nasl");
  script_mandatory_keys("XnView/Win/Ver");
  script_xref(name:"URL", value:"http://www.xnview.com/en/xnview/#downloads");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

if(!version = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:version, test_version:"2.04"))
{
  report = report_fixed_ver(installed_version:version, fixed_version:"2.04");
  security_message(port: 0, data: report);
  exit(0);
}
