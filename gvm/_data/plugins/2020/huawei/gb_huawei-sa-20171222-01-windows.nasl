# Copyright (C) 2020 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108790");
  script_version("2020-06-06T12:09:29+0000");
  script_tag(name:"last_modification", value:"2020-06-06 12:09:29 +0000 (Sat, 06 Jun 2020)");
  script_tag(name:"creation_date", value:"2020-06-05 08:17:40 +0000 (Fri, 05 Jun 2020)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2010-2729");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Huawei Data Communication: Remote Code Execution Vulnerability in Microsoft Windows Print Spooler Service (huawei-sa-20171222-01-windows)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei");
  script_dependencies("gb_huawei_vrp_network_device_consolidation.nasl");
  script_mandatory_keys("huawei/vrp/detected");

  script_tag(name:"summary", value:"Microsoft released a security bulletin MS10-061 to publicly disclose a remote code execution vulnerability in the Print Spooler service.");

  script_tag(name:"insight", value:"Microsoft released a security bulletin MS10-061 to publicly disclose a remote code execution vulnerability in the Print Spooler service. The vulnerability could allow remote code execution if an attacker sends a specially crafted print request to a vulnerable system. (Vulnerability ID: HWPSIRT-2017-05163)This vulnerability has been assigned a Common Vulnerabilities and Exposures (CVE) ID: CVE-2010-2729.Huawei has released software updates to fix this vulnerability. This advisory is available in the linked references.");

  script_tag(name:"impact", value:"Successful exploit may result in remote code execution.");

  script_tag(name:"affected", value:"AnyOffice versions V200R002C10 V200R002C20 V200R005C02

SMC2.0 versions V100R003C10 V100R005C00 V500R002C00

Secospace AntiDDoS8000 versions V100R001C00 V500R001C00 V500R001C20 V500R001C60 V500R001C80

Secospace AntiDDoS8160 versions V100R001C00SPC300");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_xref(name:"URL", value:"https://www.huawei.com/en/psirt/security-advisories/huawei-sa-20171222-01-windows-en");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

# nb: Unknown device (no VRP), no public vendor advisory or general inconsistent / broken data
