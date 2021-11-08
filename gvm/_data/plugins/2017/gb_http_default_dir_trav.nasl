###############################################################################
# OpenVAS Vulnerability Test
#
# Generic HTTP Directory Traversal (Web Application Check)
#
# Authors:
# Jan Philipp Schulte <jan.schulte@greenbone.net>
# Adrian Steins <adrian.steins@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.113002");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2017-09-26 10:00:00 +0200 (Tue, 26 Sep 2017)");
  script_name("Generic HTTP Directory Traversal (Web Application Check)");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "os_detection.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning", "global_settings/disable_generic_webapp_scanning");

  script_xref(name:"URL", value:"https://owasp.org/www-community/attacks/Path_Traversal");

  script_tag(name:"summary", value:"Generic check for HTTP directory traversal vulnerabilities within URL
  parameters.

  NOTE: Please enable 'Enable generic web application scanning' within the NVT 'Global variable settings'
  (OID: 1.3.6.1.4.1.25623.1.0.12288) if you want to run this script.");

  script_tag(name:"impact", value:"Successfully exploiting this issue may allow an attacker to access paths
  and directories that should normally not be accessible by a user. This can result in effects ranging from
  disclosure of confidential information to arbitrary code execution.");

  script_tag(name:"vuldetect", value:"Sends crafted HTTP requests to previously spidered URL parameters
  (e.g. /index.php?parameter=directory_traversal of a web application) and checks the response.");

  script_tag(name:"solution", value:"Contact the vendor for a solution.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("misc_func.inc");
include("host_details.inc");

# nb: We also don't want to run if optimize_test is set to "no"
if( http_is_cgi_scan_disabled() ||
    get_kb_item( "global_settings/disable_generic_webapp_scanning" ) )
  exit( 0 );

traversal = make_list( "/",
                      crap( data:"../", length:3*6 ),
                      crap( data:".../", length:4*6 ),
                      crap( data:"%2e%2e%2f", length:9*6 ),
                      crap( data:"%2e%2e/", length:6*6 ),
                      crap( data:"%2e./.%2e/", length:10*3 ),
                      crap( data:"..%2f", length:5*6 ),
                      crap( data:"..\", length:3*6 ),
                      crap( data:"...\", length:4*6 ),
                      crap( data:"%2e%2e%5c", length:9*6 ),
                      crap( data:"%2e%2e\", length:7*6 ),
                      crap( data:"..%5c", length:5*6 ),
                      crap( data:"..%255c", length:7*6 ),
                      crap( data:"%c0%ae%c0%ae/", length:13*6 ), # nb: JVM UTF-8 bug for various products, see e.g. 2011/gb_trend_micro_data_loss_prevention_48225.nasl or 2018/apache/gb_apache_tomcat_30633.nasl
                      crap( data:"%252e%252e%255c", length:15*6 ) );

files = traversal_files();

port = http_get_port( default:80 );
host = http_host_name( dont_add_port:TRUE );
cgis = http_get_kb_cgis( port:port, host:host );
if( ! cgis )
  exit( 0 );

foreach cgi( cgis ) {
  cgiArray = split( cgi, sep:" ", keep:FALSE );
  foreach trav( traversal ) {
    foreach file( keys( files ) ) {
      url = trav + files[file];
      urls = http_create_exploit_req( cgiArray:cgiArray, ex:url );
      foreach url( urls ) {
        if( http_vuln_check( port:port, url:url, pattern:file ) ) {
          report = http_report_vuln_url( port:port, url:url );
          security_message( port:port, data:report );
          exit( 0 );
        }
      }
    }
  }
}

exit( 0 );
