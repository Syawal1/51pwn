###############################################################################
# OpenVAS Vulnerability Test
#
# Nagios Network Analyzer Detection
#
# Authors:
# Tameem Eissa <tameem.eissa@greenbone.net>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.107062");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2016-10-19 13:26:09 +0700 (Wed, 19 Oct 2016)");
  script_name("Nagios Network Analyzer Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"This script performs an HTTP based detection of Nagios Network Analyzer");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("host_details.inc");

port = http_get_port(default:80);

if(!http_can_host_php(port:port)) exit(0);

foreach dir(make_list_unique("/nagiosna", "/nagios", http_cgi_dirs(port:port))) {

  install = dir;
  if( dir == "/" ) dir = "";

  url = dir + "/index.php/login";
  req = http_get(item:url, port:port);
  buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
  if( ! buf ) continue;

  if (buf =~ "^HTTP/1\.[01] 200" && "<title>Login &bull; Nagios Network Analyzer</title>" >< buf
      && "nnalogo_small.png" >< buf && ('<div class="demosplash"></div>' >< buf || '<div class="loginsplash"></div>')) {

    set_kb_item(name:"nagiosna/installed", value:TRUE);

    if ('<div class="demosplash"></div>' >< buf) {
      extra = "Demo Version";
    }

    vers = "unknown";
    version = eregmatch(string:buf, pattern:'var NA_VERSION = "([0-9.]+)"', icase:TRUE);

    if (isnull(version[1])) {
      version = eregmatch(string: buf, pattern: 'ver=([0-9.]+)">');
    }

    if (!isnull(version[1])) {
      vers = chomp(version[1]);
      set_kb_item(name:"www/" + port + "/nagiosna", value:vers + " under " + install);
    }

    cpe = build_cpe(value:vers, exp:"^([0-9.]+)", base:"cpe:/a:nagios:nagiosna:");
    if(isnull(cpe))
      cpe = 'cpe:/a:nagios:nagiosna:';

    register_product(cpe:cpe, location:install, port:port, service:'www');

    log_message(data:build_detection_report(app:"Nagios Network Analyzer",
                                            version:vers,
                                            install:install,
                                            cpe:cpe,
                                            concluded:version[0],
                                            extra:extra),
                                            port:port);
  }
}

exit(0);
