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
  script_oid("1.3.6.1.4.1.25623.1.0.108774");
  script_version("2020-06-06T12:09:29+0000");
  script_tag(name:"last_modification", value:"2020-06-06 12:09:29 +0000 (Sat, 06 Jun 2020)");
  script_tag(name:"creation_date", value:"2020-06-05 08:17:40 +0000 (Fri, 05 Jun 2020)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_cve_id("CVE-2017-2722");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Huawei Data Communication: Input Validation Vulnerability in Multiple Huawei Products (huawei-sa-20170419-01-pse)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei");
  script_dependencies("gb_huawei_vrp_network_device_consolidation.nasl");
  script_mandatory_keys("huawei/vrp/detected");

  script_tag(name:"summary", value:"There is an input validation vulnerability in Huawei Multiple products.");

  script_tag(name:"insight", value:"There is an input validation vulnerability in Huawei Multiple products. Due to the lack of input validation on the device, a remote attacker may exploit this vulnerability by crafting a malformed packet and sending it to the device. A successful exploit could allow the attacker to cause a denial of service or execute arbitrary code. (Vulnerability ID: HWPSIRT-2016-12105)This vulnerability has been assigned a Common Vulnerabilities and Exposures (CVE) ID: CVE-2017-2722.Huawei has released software updates to fix this vulnerability. This advisory is available in the linked references.");

  script_tag(name:"impact", value:"An attacker can exploit this vulnerability to cause a denial of service or execute arbitrary code.");

  script_tag(name:"affected", value:"DBS3900 TDD LTE versions V100R003C00 V100R004C10

DP300 versions V500R002C00

TE60 versions V100R001C01SPC100 V100R001C10 V100R003C00 V500R002C00 V600R006C00

TP3106 versions V100R001C06B020 V100R002C00

eSpace 7950 versions V200R003C00 V200R003C30

eSpace IAD versions V300R001C07SPCa00 V300R002C01SPCb00

eSpace U1981 versions V100R001C20SPC500 V100R001C30 V200R003C00 V200R003C00SPC200 V200R003C20SPH502 V200R003C30 V200R003C30SPC100");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_xref(name:"URL", value:"https://www.huawei.com/en/psirt/security-advisories/huawei-sa-20170419-01-pse-en");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

# nb: Unknown device (no VRP), no public vendor advisory or general inconsistent / broken data
