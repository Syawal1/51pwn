###############################################################################
# OpenVAS Vulnerability Test
#
# Pulse Connect Secure 'diag.cgi' Cross-Site Request Forgery Vulnerability
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:juniper:pulse_connect_secure";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811738");
  script_version("2020-08-04T07:53:04+0000");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-08-04 07:53:04 +0000 (Tue, 04 Aug 2020)");
  script_tag(name:"creation_date", value:"2017-09-12 10:21:00 +0530 (Tue, 12 Sep 2017)");

  script_cve_id("CVE-2017-11455");
  script_bugtraq_id(100530);

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Pulse Connect Secure 'diag.cgi' Cross-Site Request Forgery Vulnerability");

  script_tag(name:"summary", value:"Pulse Connect Secure is prone to cross-site request forgery vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to improper input validation in 'diag.cgi' script.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to hijack the authentication of administrators for requests to start
  tcpdump, related to the lack of anti-CSRF tokens. A remote user can create a
  specially crafted HTML page or URL that, when loaded by the target authenticated
  user, will trigger a flaw in 'diag.cgi' and take actions on the target interface
  acting as the target user.");

  script_tag(name:"affected", value:"Pulse Connect Secure 8.3x prior to 8.3R1,
  8.2x prior to 8.2R6, 8.1x prior to 8.1R12 and 8.0x prior to 8.0R17.");

  script_tag(name:"solution", value:"Upgrade Pulse Connect Secure to 8.3R1, 8.2R6, 8.1R12, 8.0R17 or later.");

  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1039242");
  script_xref(name:"URL", value:"https://kb.pulsesecure.net/articles/Pulse_Security_Advisories/SA40793");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_pulse_connect_secure_consolidation.nasl");
  script_mandatory_keys("pulsesecure/detected");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");
include("revisions-lib.inc");

if (!version = get_app_version(cpe:CPE, nofork: TRUE))
  exit(0);

if (version =~ "^8\.3" && version_is_less(version: version, test_version: "8.3r1"))
  fix = "8.3R1";

if (version =~ "^8\.2" && version_is_less(version: version, test_version: "8.2r6"))
  fix = "8.2R6";

if (version =~ "^8\.1" && version_is_less(version: version, test_version: "8.1r12"))
  fix = "8.1R12";

if (version =~ "^8\.0" && version_is_less(version: version, test_version: "8.0r17"))
  fix = "8.0R17";

if (fix) {
  report = report_fixed_ver(installed_version: toupper(version), fixed_version: fix);
  security_message(data: report, port: 0);
  exit(0);
}

exit(99);
