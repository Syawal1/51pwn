###############################################################################
# OpenVAS Vulnerability Test
#
# CMS Made Simple Local File Include and Cross Site Scripting Vulnerabilities
#
# Authors:
# Michael Meyer
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

CPE = "cpe:/a:cmsmadesimple:cms_made_simple";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100498");
  script_version("2020-04-24T07:24:50+0000");
  script_tag(name:"last_modification", value:"2020-04-24 07:24:50 +0000 (Fri, 24 Apr 2020)");
  script_tag(name:"creation_date", value:"2010-02-17 20:53:20 +0100 (Wed, 17 Feb 2010)");
  script_bugtraq_id(38234);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("CMS Made Simple Local File Include and Cross Site Scripting Vulnerabilities");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/38234");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("cms_made_simple_detect.nasl");
  script_mandatory_keys("cmsmadesimple/installed");

  script_tag(name:"summary", value:"CMS Made Simple is prone to a local file-include vulnerability and a
  cross-site scripting vulnerability because it fails to properly sanitize user-supplied input.");

  script_tag(name:"impact", value:"An attacker can exploit the local file-include vulnerability using directory-traversal strings to view and execute
  local files within the context of the webserver process. Information harvested may aid in further attacks.

  The attacker may leverage the cross-site scripting issue to execute arbitrary script code in the browser of an
  unsuspecting user in the context of the affected site. This may let the attacker steal cookie-based authentication
  credentials and launch other attacks.");

  script_tag(name:"affected", value:"CMS Made Simple 1.6.6 is affected. Other versions may also be vulnerable.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since
  the disclosure of this vulnerability. Likely none will be provided anymore. General solution options
  are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!vers = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less_equal(version: vers, test_version: "1.6.6")) {
  report = report_fixed_ver(installed_version:vers, vulnerable_range:"Less or equal to 1.6.6");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
