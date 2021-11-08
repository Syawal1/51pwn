###############################################################################
# OpenVAS Vulnerability Test
#
# Adobe Experience Manager Remote Version Detection
#
# Authors:
# Rinu Kuriaksoe <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807067");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2016-02-11 14:43:49 +0530 (Thu, 11 Feb 2016)");
  script_name("Adobe Experience Manager Remote Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detects the installed version of
  Adobe Experience Manager.

  This script sends an HTTP GET request and tries to get the version from the
  response.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("host_details.inc");

port = http_get_port( default:80 );
host = http_host_name( dont_add_port:TRUE );

url = "/libs/granite/core/content/login.html?";

sndReq = http_get( item:url, port:port );
rcvRes = http_keepalive_send_recv( port:port, data:sndReq );

if( rcvRes =~ "HTTP/1\.. 200" && ( "<title>AEM Sign In" >< rcvRes ||
    ( ">Welcome to Adobe Experience Manager<" >< rcvRes && "Adobe Systems" >< rcvRes ) ||
    'src="/etc/clientlibs/granite/' >< rcvRes || 'href="/etc/clientlibs/granite/' >< rcvRes ) ) {

  version = "unknown";
  install = "/";
  set_kb_item( name:"AEM/Installed", value:TRUE );
  concludedUrl = '\n' + http_report_vuln_url( port:port, url:url, url_only:TRUE );

  foreach url( make_list( "/system/console", "/system/console/configMgr", "/system/console/bundles" ) ) {
    sndReq = http_get( item:url, port:port );
    rcvRes = http_keepalive_send_recv( port:port, data:sndReq );
    if( rcvRes =~ "HTTP/1.. 401" && "OSGi Management Console" >< rcvRes ) {
      set_kb_item( name:"www/content/auth_required", value:TRUE );
      set_kb_item( name:"www/" + host + "/" + port + "/content/auth_required", value:url );
      extra = "The OSGi Management Console is reachable at: " + http_report_vuln_url( port:port, url:url, url_only:TRUE );
      break;
    }
  }

  url = "/system/sling/cqform/defaultlogin.html";
  sndReq = http_get( item:url, port:port );
  rcvRes = http_keepalive_send_recv( port:port, data:sndReq );
  if( rcvRes =~ "HTTP/1.. 200" && "QUICKSTART_HOMEPAGE" >< rcvRes ) {
    extra += '\nThe Sling console is reachable at: ' + http_report_vuln_url( port:port, url:url, url_only:TRUE );
  }

  url = "/crx/de/index.jsp";
  sndReq = http_get( item:url, port:port );
  rcvRes = http_keepalive_send_recv( port:port, data:sndReq );
  if( rcvRes =~ "HTTP/1.. 200" && ( "<title>CRXDE Lite</title>" >< rcvRes || "icons/crxde_favicon.ico" >< rcvRes ) ) {
    extra += '\nThe CRXDE console is reachable at: ' + http_report_vuln_url( port:port, url:url, url_only:TRUE );
  }

  cpe = "cpe:/a:adobe:experience_manager";
  register_product( cpe:cpe, location:install, port:port, service:"www" );

  log_message( data:build_detection_report( app:"Adobe Experience Manager",
                                            version:version,
                                            install:install,
                                            cpe:cpe,
                                            concludedUrl:concludedUrl,
                                            extra:extra ),
                                            port:port );
}

exit( 0 );
