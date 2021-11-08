###############################################################################
# OpenVAS Vulnerability Test
#
# osCommerce Detection
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (C) 2009 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.100001");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2009-02-26 04:52:45 +0100 (Thu, 26 Feb 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("osCommerce Detection");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("Product detection");
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"This host is running osCommerce, a widely installed open source shopping e-commerce solution.");
  script_xref(name:"URL", value:"http://www.oscommerce.com");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("host_details.inc");

port = http_get_port(default:80);

x=0;

foreach dir( make_list_unique("/", "/osc", "/oscommerce", "/store", "/catalog", "/shop", http_cgi_dirs( port:port ) ) ) {

 install = dir;
 if( dir == "/" ) dir = "";

 url = dir + "/index.php";
 buf = http_get_cache(item:url, port:port);
 if( ! buf ) continue;

 if( buf =~ "^HTTP/1\.[01] 200" && ( "osCsid" >< buf || buf =~ "Powered by.*osCommerce" ) ) {
   installations[x] = install;
 }
 x++;
}

cpe = 'cpe:/a:oscommerce:oscommerce';

if(installations)
{
  info = string("\n\nOsCommerce was detected on the remote host in the following directory(s):\n\n");
  foreach found (installations) {
    set_kb_item(name:"Software/osCommerce", value: TRUE);
    info += string(found, "\n");
    set_kb_item(name:"Software/osCommerce/dir", value: found);
    set_kb_item(name: string("www/", port, "/oscommerce"), value: string("unknown under ",found));
    register_product( cpe:cpe, location:found, port:port, service:"www" );
  }

  log_message(port:port,data:info);
  exit(0);
}

exit(0);
