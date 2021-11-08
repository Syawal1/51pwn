###############################################################################
# OpenVAS Vulnerability Test
#
# Multiple Toshiba e-Studio Devices Security Bypass Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (C) 2011 Greenbone Networks GmbH
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103301");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2011-10-18 13:33:12 +0200 (Tue, 18 Oct 2011)");
  script_bugtraq_id(50168);

  script_name("Multiple Toshiba e-Studio Devices Security Bypass Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50168");
  script_xref(name:"URL", value:"http://www.eid.toshiba.com.au/n_mono_search.asp");

  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_family("General");
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 8080);
  script_mandatory_keys("TOSHIBA/banner");

  script_tag(name:"summary", value:"Multiple Toshiba e-Studio devices are prone to a security-bypass
  vulnerability.");

  script_tag(name:"impact", value:"Successful exploits will allow attackers to bypass certain security
  restrictions and gain access in the context of the device.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the
  disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to
  upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("host_details.inc");

port = http_get_port(default:8080);

banner = http_get_remote_headers(port:port);
if(!banner || "Server: TOSHIBA" >!< banner)exit(0);

url = string("/TopAccess//Administrator/Setup/ScanToFile/List.htm");

if(http_vuln_check(port:port, url:url, pattern:"<TITLE>Save as file Setting",extra_check:make_list("Password","Protocol","Server Name"))) {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(0);
