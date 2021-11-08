# OpenVAS Vulnerability Test
# Description: GlobalSCAPE Secure FTP Server User Input Overflow
#
# Authors:
# Gareth Phillips - SensePost (www.sensepost.com)
# changes by Tenable:
#  - Fixed regex
#
# Copyright:
# Copyright (C) 2005 SensePost
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.18627");
  script_version("2020-08-24T08:40:10+0000");
  script_tag(name:"last_modification", value:"2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2005-1415");
  script_bugtraq_id(13454);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("GlobalSCAPE Secure FTP Server User Input Overflow");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("Copyright (C) 2005 SensePost");
  script_family("Gain a shell remotely");
  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp/globalscape/secure_ftp/detected");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Upgrade to newest release of this software.");

  script_tag(name:"summary", value:"The remote host is running GlobalSCAPE Secure FTP Server.

  GlobalSCAPE Secure FTP Server 3.0.2 and prior versions are affected by a buffer overflow
  due to mishandling the user-supplied input.");

  script_tag(name:"impact", value:"An attacker would first need to authenticate to the server before
  they can execute arbitrary commands.");

  exit(0);
}

include("ftp_func.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = ftp_get_port(default:21);
ftpbanner = ftp_get_banner(port:port);
if ( ftpbanner && egrep(pattern:"^220 GlobalSCAPE Secure FTP Server \(v. 3(.0|\.0\.[0-2])\)",string:ftpbanner) )
  security_message(port);
