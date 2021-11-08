# OpenVAS Vulnerability Test
# Description: mod_ssl hook functions format string vulnerability
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
# based on work from (C) Tenable Network Security
#
# Copyright:
# Copyright (C) 2004 David Maciejak
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
  script_oid("1.3.6.1.4.1.25623.1.0.13651");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(10736);
  script_cve_id("CVE-2004-0700");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("mod_ssl hook functions format string vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2004 David Maciejak");
  script_family("Gain a shell remotely");
  script_dependencies("secpod_apache_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("apache/installed");

  script_tag(name:"solution", value:"Upgrade to version 2.8.19 or newer.");

  script_tag(name:"summary", value:"The remote host is using a version vulnerable of mod_ssl which is
  older than 2.8.19. There is a format string condition in the
  log functions of the remote module which may allow an attacker to
  execute arbitrary code on the remote host.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");

port = http_get_port(default:80);

banner = http_get_remote_headers(port:port);
if(!banner)
  exit(0);

if("Darwin" >< banner)
  exit(0);

serv = strstr(banner, "Server");
if("Apache/" >!< serv )
  exit(0);

if("Apache/2" >< serv)
  exit(0);

if("Apache-AdvancedExtranetServer/2" >< serv)
  exit(0);

if(ereg(pattern:".*mod_ssl/(1.*|2\.([0-7]\..*|8\.([0-9]|1[0-8])[^0-9])).*", string:serv)) {
  security_message(port:port);
  exit(0);
}

exit(99);