##############################################################################
# OpenVAS Vulnerability Test
#
# FreePHPBlogSoftware 'default_theme.php' Remote File Inclusion Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.902056");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2010-05-28 16:52:49 +0200 (Fri, 28 May 2010)");
  script_cve_id("CVE-2010-1978");
  script_bugtraq_id(39233);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("FreePHPBlogSoftware 'default_theme.php' Remote File Inclusion Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/39321");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/57560");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"insight", value:"The flaw is due to error an in 'default_theme.php' script, which
  fails to properly sanitize user input supplied to the 'phpincdir' parameter.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"This host is running FreePHPBlogSoftware and is prone to remote
  file inclusion Vulnerability");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to include
  arbitrary remote file containing malicious PHP code and execute it in the
  context of the webserver process.");

  script_tag(name:"affected", value:"FreePHPBlogSoftware version 1.0");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_banner");
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

foreach dir (make_list_unique("/fpws", "/FPWS", "/", http_cgi_dirs(port:port)))
{

  if(dir == "/") dir = "";

  res = http_get_cache(item: dir + "/index.php", port:port);

  if (">FreePHPBlogSoftware<" >< res)
  {
    req = http_get(item: dir + "/includes/themes_meta.inc", port:port);
    res = http_keepalive_send_recv(port:port, data:req);

    version = eregmatch(pattern:"Version: ([0-9.]+)" , string:res);
    if(version[1] != NULL)
    {
      if(version_is_equal(version:version[1], test_version:"1.0")){
        security_message(port:port);
        exit(0);
      }
    }
  }
}

exit(99);
