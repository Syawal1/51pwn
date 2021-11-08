##############################################################################
# OpenVAS Vulnerability Test
#
# Textpattern CMS 'index.php' Remote File Inclusion Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.801442");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2010-11-11 07:48:04 +0100 (Thu, 11 Nov 2010)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2010-3205");
  script_name("Textpattern CMS 'index.php' Remote File Inclusion Vulnerability");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/61475");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/14823/");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/1008-exploits/textpattern-rfi.txt");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"insight", value:"The flaw is due to an error in 'index.php', which is not properly
  sanitizing user-supplied data via 'inc' parameter. This allows an attacker to
  include arbitrary files.");

  script_tag(name:"solution", value:"Upgrade to version 4.3.0 or later.");

  script_tag(name:"summary", value:"This host is running Textpattern and is prone to remote file
  inclusion vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary
  code on the vulnerable Web server.");

  script_tag(name:"affected", value:"Textpattern CMS version 4.2.0");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");
  script_xref(name:"URL", value:"http://textpattern.com/download");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("version_func.inc");

port = http_get_port(default:80);

if(!http_can_host_php(port:port)){
  exit(0);
}

foreach dir (make_list_unique("/textpattern", "/", http_cgi_dirs(port:port)))
{

  if(dir == "/") dir = "";

  res = http_get_cache(item: dir + "/index.php", port:port);

  if(">Textpattern<" >< res || "Textpattern CMS" >< res)
  {
    req = http_get(item: dir + "/README.txt", port:port);
    res = http_keepalive_send_recv(port:port, data:req);

    version = eregmatch(pattern:"Textpattern ([0-9.]+)", string:res);
    if(version[1] != NULL)
    {
      if(version_is_equal(version:version[1], test_version:"4.2.0"))
      {
        security_message(port:port);
        exit(0);
      }
    }
  }
}

exit(99);
