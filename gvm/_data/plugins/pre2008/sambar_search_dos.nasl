###############################################################################
# OpenVAS Vulnerability Test
#
# Sambar Search Results Buffer Overflow Denial of Service
#
# Authors:
# Gareth Phillips - SensePost (www.sensepost.com)
# changes by Tenable:
# - Longer regex to match on
# - Also match on the server version number
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
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.18650");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(7975, 9607);
  script_cve_id("CVE-2004-2086");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Sambar Search Results Buffer Overflow Denial of Service");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2005 SensePost");
  script_family("Denial of Service");
  script_dependencies("gb_sambar_server_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("sambar_server/detected");

  script_tag(name:"affected", value:"Sambar Server 4.x, Sambar Server 5.x, Sambar Server 6.0.");

  script_tag(name:"solution", value:"Upgrade to current release of this software.");

  script_tag(name:"summary", value:"The remote host is running Sambar Server, a web server package.

  The remote version of this software contains a flaw that may allow an attacker
  to crash the service remotely.

  A buffer overflow was found in the /search/results.stm application that
  comes shipped with Sambar Server.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port( default:80 );

url = "/search/results.stm";
req = http_get( item:url, port:port );
res = http_keepalive_send_recv( port:port, data:req );
if(!res)
  exit( 0 );

if( egrep( pattern:"^Server: SAMBAR (4\.|5\.[01])", string:res, icase:TRUE ) ) {
  report = http_report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
} else if( egrep( pattern:"&copy; 1997-(199[8-9]|200[0-3]) Sambar Technologies, Inc. All rights reserved.", string:res ) ) {
  report = http_report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
} else {
  exit( 99 );
}
