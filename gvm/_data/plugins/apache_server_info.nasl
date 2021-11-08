###############################################################################
# OpenVAS Vulnerability Test
#
# Apache /server-info accessible
#
# Authors:
# Vincent Renardias <vincent@strongholdnet.com>
#
# Copyright:
# Copyright (C) 2005 StrongHoldNet
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
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10678");
  script_version("2020-12-01T08:44:58+0000");
  script_tag(name:"last_modification", value:"2020-12-01 13:31:42 +0000 (Tue, 01 Dec 2020)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Apache /server-info accessible");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2005 StrongHoldNet");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://httpd.apache.org/docs/current/mod/mod_info.html");

  script_tag(name:"summary", value:"Requesting the URI /server-info provides a comprehensive overview
  of the server configuration.");

  script_tag(name:"insight", value:"server-info is a Apache HTTP Server handler provided by the
  'mod_info' module and used to retrieve the server's configuration.");

  script_tag(name:"impact", value:"Requesting the URI /server-info gives throughout information about
  the currently running Apache to an attacker.");

  script_tag(name:"affected", value:"All Apache installations with an enabled 'mod_info' module.");

  script_tag(name:"vuldetect", value:"Checks if the /server-info page of Apache is accessible.");

  script_tag(name:"solution", value:"- If this feature is unused commenting out the appropriate section in
  the web servers configuration is recommended.

  - If this feature is used restricting access to trusted clients is recommended.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"Workaround");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port( default:80 );

url = "/server-info";

buf = http_get_cache( item:url, port:port );

if( "Apache Server Information" >< buf ) {

  sv = eregmatch( pattern:'Server Version:([ /<>a-zA-Z0-9+="]+)<tt>([^<]+)</tt>', string:buf );

  if( ! isnull( sv[2] ) ) {
    set_kb_item( name:"www/server-info/banner/" + port, value:"Server: " + sv[2] );
    set_kb_item( name:"apache_or_server-info/banner", value:TRUE );
  }

  report = http_report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
