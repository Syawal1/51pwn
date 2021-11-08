###############################################################################
# OpenVAS Vulnerability Test
#
# WordPress UpdraftPlus Plugin Multiple Vulnerabilities
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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
  script_oid("1.3.6.1.4.1.25623.1.0.140535");
  script_version("2020-04-21T10:50:58+0000");
  script_tag(name:"last_modification", value:"2020-04-21 10:50:58 +0000 (Tue, 21 Apr 2020)");
  script_tag(name:"creation_date", value:"2017-11-24 13:22:19 +0700 (Fri, 24 Nov 2017)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2017-16870", "CVE-2017-16871");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("WordPress UpdraftPlus Plugin Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");

  script_tag(name:"summary", value:"These CVE's have been disputed.

  WordPress UpdraftPlus plugin is prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"WordPress UpdraftPlus plugin is prone to multiple vulnerabilities:

  - The UpdraftPlus plugin for WordPress has SSRF in the updraft_ajax_handler function in
  /wp-content/plugins/updraftplus/admin.php via an httpget subaction. (CVE-2017-16870)

  - The UpdraftPlus plugin for WordPress allows remote PHP code execution because the plupload_action function in
  /wp-content/plugins/updraftplus/admin.php has a race condition before deleting a file associated with the name
  parameter. (CVE-2017-16871)");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"WordPress Loginizer plugin version 1.13.12 and prior.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  # The CVE has been disputed
  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
