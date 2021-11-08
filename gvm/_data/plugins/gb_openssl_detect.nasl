###############################################################################
# OpenVAS Vulnerability Test
#
# OpenSSL Version Detection (Remote)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.806723");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2015-11-24 16:05:56 +0530 (Tue, 24 Nov 2015)");
  script_name("OpenSSL Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("OpenSSL/banner");
  script_require_ports("Services/www", 443);

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"summary", value:"Detects the installed version of
  OpenSSL.

  This script sends an HTTP GET request and tries to get the version from the
  response.");

  exit(0);
}

include("cpe.inc");
include("http_func.inc");
include("port_service_func.inc");
include("host_details.inc");

function version_already_detected(v, k) {

  local_var v, k;

  if(!v)
    return;

  foreach vers(k)
    if(v == vers)
      return TRUE;

  return;
}

ad = make_list();
ports = http_get_ports(default_port_list:make_list(443));

foreach port(ports) {

  banner = http_get_remote_headers(port:port);

  if(banner && "OpenSSL/" >< banner) {

    version = "unknown";
    install = port + "/tcp";

    vers = eregmatch(pattern:'OpenSSL/([0-9]+[^ \r\n]+)', string:banner);
    if(vers[1])
      version = vers[1];

    set_kb_item(name:"openssl/detected", value:TRUE);
    set_kb_item(name:"openssl_or_gnutls/detected", value:TRUE);

    if(!version_already_detected(v:version, k:ad)) { # register any version only once

      cpe = build_cpe(value:version, exp:"^([0-9a-z.-]+)", base:"cpe:/a:openssl:openssl:");
      if(!cpe)
        cpe = "cpe:/a:openssl:openssl";

      ad = make_list(ad, version);
      register_product(cpe:cpe, location:install, port:port, service:"www");
      log_message(data:build_detection_report(app:"OpenSSL",
                                              version:version,
                                              install:install,
                                              cpe:cpe,
                                              concluded:vers[0]),
                                              port:port);
    }
  }
}

exit(0);
