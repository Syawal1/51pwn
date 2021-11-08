# OpenVAS Vulnerability Test
# Description: RaidenHTTPD directory traversal
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
#
# Copyright:
# Copyright (C) 2005 David Maciejak
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
  script_oid("1.3.6.1.4.1.25623.1.0.16313");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(12451);
  script_xref(name:"OSVDB", value:"13575");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_name("RaidenHTTPD directory traversal");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2005 David Maciejak");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("RaidenHTTPD/banner");
  script_require_ports("Services/www", 80);

  script_tag(name:"solution", value:"Upgrade to RaidenHTTPD version 1.1.31.");

  script_tag(name:"summary", value:"The remote host is running a version of RaidenHTTPD which is
  vulnerable to a remote directory traversal bug.");

  script_tag(name:"impact", value:"An attacker exploiting this bug would be able to gain access to potentially
  confidential material outside of the web root.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default:80);

banner = http_get_remote_headers(port:port);
# Server: RaidenHTTPD/1.1.31 (Shareware)
if( ! banner || "RaidenHTTP" >!< banner )
  exit(0);

foreach file(make_list("windows/system.ini", "winnt/system.ini")) {

  req = http_get(item:file, port:port);
  res = http_keepalive_send_recv(data:req, port:port);

  if("[drivers]" >< tolower(res)) {
    report = http_report_vuln_url(port:port, data:report);
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);
