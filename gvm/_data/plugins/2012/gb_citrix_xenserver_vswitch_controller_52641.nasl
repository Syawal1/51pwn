###############################################################################
# OpenVAS Vulnerability Test
#
# Citrix XenServer vSwitch Controller Component Multiple Vulnerabilities
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
  script_oid("1.3.6.1.4.1.25623.1.0.103474");
  script_bugtraq_id(52641);
  script_version("2020-08-24T15:18:35+0000");
  script_name("Citrix XenServer vSwitch Controller Component Multiple Vulnerabilities");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2012-04-23 11:36:51 +0200 (Mon, 23 Apr 2012)");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/52641");
  script_xref(name:"URL", value:"http://www.citrix.com/English/ps2/products/feature.asp?contentID=1686939");
  script_xref(name:"URL", value:"http://support.citrix.com/article/CTX132476");

  script_tag(name:"summary", value:"Citrix XenServer is prone to multiple unspecified vulnerabilities.");

  script_tag(name:"impact", value:"The impact of these issues is currently unknown.");

  script_tag(name:"affected", value:"Citrix XenServer versions 5.6, 5.6 FP 1, 5.6 SP 2, and 6 are
  vulnerable.");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more information.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("host_details.inc");

port = http_get_port(default:443);

foreach dir( make_list_unique( "/", http_cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  url = dir + '/login';
  req = http_get(item:url, port:port);
  buf = http_keepalive_send_recv(port:port, data:req);

  if("DVSC_MGMT_UI_SESSION" >!< buf && buf !~ "<title>.*DVS.*Controller") {
    continue;
  }

  url = dir + '/static/';
  req = http_get(item:url, port:port);
  buf = http_keepalive_send_recv(port:port, data:req);

  if("Directory listing for /static" >!< buf) {
    continue;
  }

  lines = split(buf);
  locs = make_list();

  foreach line (lines) {
    if(locs = eregmatch(pattern:'<a href="([0-9]+)/">', string:line)) {
      loc[i++] = locs[1];
    }
  }

  foreach l (loc) {

    url = '/static/' + l + '/nox/ext/apps/vmanui/main.js';
    req = http_get(item:url, port:port);
    buf = http_keepalive_send_recv(port:port, data:req);

    if('dojo.provide("nox.ext.apps.vmanui.main")' >< buf) {
      if("X-CSRF-Token" >!< buf && "oCsrfToken" >!< buf) {
        report = http_report_vuln_url(port:port, url:url);
        security_message(port:port, data:report);
        exit(0);
      }
    }
  }
}

exit(99);
