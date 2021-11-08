###############################################################################
# OpenVAS Vulnerability Test
#
# Mongoose Web Server Source Code Disclosure Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.800412");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2010-01-09 13:17:56 +0100 (Sat, 09 Jan 2010)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2009-4530", "CVE-2009-4535");
  script_name("Mongoose Web Server Source Code Disclosure Vulnerability");
  script_xref(name:"URL", value:"http://freetexthost.com/0lcsrgt3vw");
  script_xref(name:"URL", value:"http://secunia.com/advisories/36934");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80, 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to display the source code
  of arbitrary files instead of an expected HTML response.");

  script_tag(name:"affected", value:"Mongoose Web Server version 2.8 and prior on Windows.");

  script_tag(name:"insight", value:"The issue is due to an error within the handling of HTTP requests and
  can be exploited to disclose the source code of certain scripts (e.g. PHP) by
  appending '::$DATA' or '/' to a URI.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"The host is running Mongoose Web Server and is prone to Source Code
  Disclosure vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default:80);

url = "/index.php::$DATA";
req = http_get(item:url, port:port);
res = http_keepalive_send_recv(port:port, data:req);
if(!isnull(res) && "<?php" >< res && "?>" >< res) {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
