###############################################################################
# OpenVAS Vulnerability Test
#
# BLOG:CMS Multiple Cross Site Scripting Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (C) 2011 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.103178");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2011-06-08 13:54:32 +0200 (Wed, 08 Jun 2011)");
  script_bugtraq_id(48132);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("BLOG:CMS Multiple Cross Site Scripting Vulnerabilities");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48132");
  script_xref(name:"URL", value:"http://blogcms.com/");
  script_xref(name:"URL", value:"http://www.rul3z.de/advisories/SSCHADV2011-007.txt");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more information.");

  script_tag(name:"summary", value:"BLOG:CMS is prone to multiple cross-site scripting vulnerabilities
  because it fails to properly sanitize user-supplied input.");

  script_tag(name:"impact", value:"An attacker may leverage these issues to execute arbitrary script code
  in the browser of an unsuspecting user in the context of the affected site. This may let the attacker
  steal cookie-based authentication credentials and launch other attacks.");

  script_tag(name:"affected", value:"BLOG:CMS 4.2.1.f is vulnerable. Other versions may also be affected.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod", value:"50"); # Prone to false positives

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("misc_func.inc");

port = http_get_port( default:80 );
if( ! http_can_host_php( port:port ) ) exit( 0 );

vt_strings = get_vt_strings();

foreach dir( make_list_unique( "/blog", "/cms", http_cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  url = dir + '/photo/templates/admin_default/confirm.tpl.php?nsextt="><script>alert(/' + vt_strings["lowercase"] + '/);</script>';

  if( http_vuln_check( port:port, url:url, pattern:"<script>alert\(/" + vt_strings["lowercase"] + "/\);</script>", check_header:TRUE ) ) {
    report = http_report_vuln_url( port:port, url:url  );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
