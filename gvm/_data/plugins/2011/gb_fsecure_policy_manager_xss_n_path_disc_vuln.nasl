###############################################################################
# OpenVAS Vulnerability Test
#
# F-Secure Policy Manager 'WebReporting' Module XSS And Path Disclosure Vulnerabilities
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.801852");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2011-03-04 14:32:35 +0100 (Fri, 04 Mar 2011)");
  script_cve_id("CVE-2011-1102", "CVE-2011-1103");
  script_bugtraq_id(46547);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("F-Secure Policy Manager 'WebReporting' Module XSS And Path Disclosure Vulnerabilities");

  script_xref(name:"URL", value:"http://secunia.com/advisories/43049");
  script_xref(name:"URL", value:"http://www.securitytracker.com/id?1025124");
  script_xref(name:"URL", value:"http://www.f-secure.com/en_EMEA/support/security-advisory/fsc-2011-2.html");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to disclose potentially sensitive
  information and execute arbitrary code in the context of an application.");

  script_tag(name:"affected", value:"F-Secure Policy Manager versions 7.x, 8.x and 9.x");

  script_tag(name:"insight", value:"The flaws are caused by an error in the 'WebReporting' interface when
  processing user-supplied requests, which could allow cross-site scripting
  and path disclosure attacks.");

  script_tag(name:"summary", value:"This host is running F-Secure Policy Manager and is prone to cross
  site scripting and path disclosure vulnerabilities.");

  script_tag(name:"solution", value:"Apply the patch for installed version from the referenced links.");

  script_xref(name:"URL", value:"ftp://ftp.f-secure.com/support/hotfix/fspm/fspm-8.00-windows-hotfix-2.zip");
  script_xref(name:"URL", value:"ftp://ftp.f-secure.com/support/hotfix/fspm/fspm-8.1x-windows-hotfix-3.zip");
  script_xref(name:"URL", value:"ftp://ftp.f-secure.com/support/hotfix/fspm/fspm-9.00-windows-hotfix-4.zip");
  script_xref(name:"URL", value:"ftp://ftp.f-secure.com/support/hotfix/fspm-linux/fspm-8.00-linux-hotfix-2.zip");
  script_xref(name:"URL", value:"ftp://ftp.f-secure.com/support/hotfix/fspm-linux/fspm-8.1x-linux-hotfix-2.zip");
  script_xref(name:"URL", value:"ftp://ftp.f-secure.com/support/hotfix/fspm-linux/fspm-9.00-linux-hotfix-2.zip");

  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("misc_func.inc");

port = http_get_port(default:8081);
res = http_get_cache(item:"/",  port:port);

if(">F-Secure Policy Manager Web Reporting<" >< res)
{
  vt_strings = get_vt_strings();

  url = "/%3Cscript%3Ealert(%27" + vt_strings["lowercase"] + "%27)%3C/script%3E";
  if(http_vuln_check(port:port, url:url,
                     pattern:"<script>alert\('" + vt_strings["lowercase"] + "'\)</script>", check_header:TRUE)){
    report = http_report_vuln_url(port:port, url:url);
    security_message(port:port, data:report);
  }
}
