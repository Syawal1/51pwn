# Copyright (C) 2019 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

CPE = "cpe:/a:teampass:teampass";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142722");
  script_version("2020-08-10T09:43:10+0000");
  script_tag(name:"last_modification", value:"2020-08-10 09:43:10 +0000 (Mon, 10 Aug 2020)");
  script_tag(name:"creation_date", value:"2019-08-09 05:35:24 +0000 (Fri, 09 Aug 2019)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_cve_id("CVE-2019-12950", "CVE-2019-16904", "CVE-2019-17203", "CVE-2019-17204", "CVE-2019-17205",
                "CVE-2020-11671", "CVE-2020-12477", "CVE-2020-12478", "CVE-2020-12479");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("TeamPass <= 2.1.27.36 Multiple XSS Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_teampass_detect.nasl");
  script_mandatory_keys("teampass/installed");

  script_tag(name:"summary", value:"TeamPass is prone to multiple cross-site scripting vulnerabilities.");

  script_tag(name:"insight", value:"These vulnerabilities exist:

  - From the sources/items.queries.php 'Import items' feature, it is possible to
    load a crafted CSV file with an XSS payload. (CVE-2019-12950)

  - Setting a crafted password for an item in a common available folder or sharing
    the item with an admin allows stored XSS. (CVE-2019-16904)

  - Setting a crafted password for an item in any folder allows stored
    XSS. (CVE-2019-17203)

  - Setting a crafted Knowledge Base label and adding any available item
    allows stored XSS. (CVE-2019-17204)

  - Placing a payload in the username field during a login attempt allows
    stored XSS. When an administrator looks at the log of failed logins,
    the XSS payload will be executed. (CVE-2019-17205)

  - Lack of authorization controls in REST API functions allows any TeamPass user with a valid API token to become
    a TeamPass administrator and read/modify all passwords via authenticated api/index.php REST API calls. (CVE-2020-11671)

  - The REST API functions allow any user with a valid API token to bypass IP address whitelist restrictions via
    an X-Forwarded-For client HTTP header to the getIp function. (CVE-2020-12477)

  - Unauthenticated attackers may retrieve files from the TeamPass web root. This may include backups or LDAP
    debug files. (CVE-2020-12478)

  - Any authenticated TeamPass user may trigger a PHP file include vulnerability via a crafted HTTP request with
    sources/users.queries.php newValue directory traversal. (CVE-2020-12479)");

  script_tag(name:"affected", value:"TeamPass version 2.1.27.36 and probably prior.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_xref(name:"URL", value:"https://github.com/nilsteampassnet/TeamPass/issues/2638");
  script_xref(name:"URL", value:"https://github.com/nilsteampassnet/TeamPass/issues/2685");
  script_xref(name:"URL", value:"https://github.com/nilsteampassnet/TeamPass/issues/2689");
  script_xref(name:"URL", value:"https://github.com/nilsteampassnet/TeamPass/issues/2690");
  script_xref(name:"URL", value:"https://github.com/nilsteampassnet/TeamPass/issues/2688");
  script_xref(name:"URL", value:"https://github.com/nilsteampassnet/TeamPass/issues/2765");
  script_xref(name:"URL", value:"https://github.com/nilsteampassnet/TeamPass/issues/2761");
  script_xref(name:"URL", value:"https://github.com/nilsteampassnet/TeamPass/issues/2764");
  script_xref(name:"URL", value:"https://github.com/nilsteampassnet/TeamPass/issues/2762");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
path = infos["location"];

if (version_is_less_equal(version: version, test_version: "2.1.27.36")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "None", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
