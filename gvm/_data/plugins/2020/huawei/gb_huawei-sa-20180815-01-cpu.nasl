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
  script_oid("1.3.6.1.4.1.25623.1.0.107834");
  script_version("2020-06-17T13:37:18+0000");
  script_tag(name:"last_modification", value:"2020-06-17 13:37:18 +0000 (Wed, 17 Jun 2020)");
  script_tag(name:"creation_date", value:"2020-05-26 15:22:01 +0200 (Tue, 26 May 2020)");
  script_tag(name:"cvss_base", value:"5.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:P/A:N");

  script_cve_id("CVE-2018-3615", "CVE-2018-3620", "CVE-2018-3646");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Huawei Data Communication: CPU Side Channel Vulnerability L1TF (huawei-sa-20180815-01-cpu)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei");
  script_dependencies("gb_huawei_vrp_network_device_consolidation.nasl");
  script_mandatory_keys("huawei/vrp/detected");

  script_tag(name:"summary", value:"Intel and security researchers publicly disclosed three new cpu side-channel vulnerabilities (CVE-2018-3615, CVE-2018-3620 and CVE-2018-3646).");

  script_tag(name:"insight", value:"Intel and security researchers publicly disclosed three new cpu side-channel vulnerabilities (CVE-2018-3615, CVE-2018-3620 and CVE-2018-3646). Successful exploit of these vulnerabilities could allow a local attacker to read the memory of other processes in specific situations. These vulnerabilities are named by researchers as 'Foreshadow' and 'Foreshadow-NG'. They are also known as L1 Terminal Fault (L1TF) in the industry. (Vulnerability ID: HWPSIRT-2018-08118, HWPSIRT-2018-08119 and HWPSIRT-2018-08120)Huawei has released software updates to fix these vulnerabilities. This advisory is available in the linked references.");

  script_tag(name:"impact", value:"Local attackers may exploit these vulnerabilities to cause information leak on the affected system.");

  script_tag(name:"affected", value:"1288H V5 versions Versions earlier than V100R005C00SPC117 (BIOS V081)

2288H V5 versions Versions earlier than V100R005C00SPC117 (BIOS V081)

2488 V5 versions Versions earlier than V100R005C00SPC500 (BIOS V095)

2488H V5 versions Versions earlier than V100R005C00SPC203 (BIOS V095)

5288 V3 versions Versions earlier than V100R003C00SPC706 (BIOS V399)

5288 V5 versions Versions earlier than V100R005C00SPC101 (BIOS V081)

BH622 V2 versions V100R002C00 Versions earlier than V100R002C00SPC308 (BIOS V519)

BH640 V2 versions Versions earlier than V100R002C00SPC306 (BIOS V519)

CH121 versions V100R001C00SPC305

CH121 V3 versions Versions earlier than V100R001C00SPC261 (BIOS V399)

CH121 V5 versions Versions earlier than V100R001C00SPC131 (BIOS V081)

CH121H V3 versions Versions earlier than V100R001C00SPC121 (BIOS V399)

CH121L V3 versions Versions earlier than V100R001C00SPC161 (BIOS V399)

CH121L V5 versions Versions earlier than V100R001C00SPC131 (BIOS V081)

CH140 V3 versions Versions earlier than V100R001C00SPC181 (BIOS V399)

CH140L V3 versions Versions earlier than V100R001C00SPC161 (BIOS V399)

CH220 V3 versions Versions earlier than V100R001C00SPC261 (BIOS V399)

CH222 V3 versions Versions earlier than V100R001C00SPC261 (BIOS V399)

CH225 V3 versions Versions earlier than V100R001C00SPC161 (BIOS V399)

CH226 V3 versions Versions earlier than V100R001C00SPC181 (BIOS V399)

CH242 V3 versions Versions earlier than V100R001C00SPC331 (BIOS V358)

CH242 V3 DDR4 versions Versions earlier than V100R001C00SPC331 (BIOS V817)

CH242 V5 versions Versions earlier than V100R001C00SPC121 (BIOS V095)

EulerOS versions V200R007C00

FusionSphere OpenStack versions V100R006C00RC3B036 V100R006C10SPC112

HUAWEI MateBook (HZ-W09/ HZ-W19/ HZ-W29) versions Versions earlier than BIOS 1.52

HUAWEI MateBook B200/ MateBook D (PL-W09/ PL-W19/ PL-W29) versions Versions earlier than BIOS 1.21

HUAWEI MateBook D (MRC-W10/ MRC-W50/ MRC-W60) versions Versions earlier than BIOS 1.19

HUAWEI MateBook X Pro (MACH-W19/ MACH-W29) versions Versions earlier than BIOS 1.12

Honor MagicBook (VLT-W50/ VLT-W60) versions Versions earlier than BIOS 1.12

RH1288 V2 versions Versions earlier than V100R002C00SPC615 (BIOS V519)

RH1288 V3 versions Versions earlier than V100R003C00SPC706 (BIOS V399)

RH1288A V2 versions Versions earlier than V100R002C00SPC708 (BIOS V519)

RH2265 V2 versions Versions earlier than V100R002C00SPC510 (BIOS V519)

RH2268 V2 versions Versions earlier than V100R002C00SPC609 (BIOS V519)

RH2285 V2 versions Versions earlier than V100R002C00SPC510 (BIOS V519)

RH2285H V2 versions Versions earlier than V100R002C00SPC510 (BIOS V519)

RH2288 V2 versions V100R002C00 Versions earlier than V100R002C00SPC609 (BIOS V519)

RH2288 V3 versions Versions earlier than V100R003C00SPC706 (BIOS V399)

RH2288A V2 versions Versions earlier than V100R002C00SPC708 (BIOS V519)

RH2288E V2 versions Versions earlier than V100R002C00SPC302 (BIOS V519)

RH2288H V2 versions Versions earlier than V100R002C00SPC619 (BIOS V519)

RH2288H V3 versions Versions earlier than V100R003C00SPC706 (BIOS V399)

RH2485 V2 versions Versions earlier than V100R002C00SPC712 (BIOS V519)

RH5885 V2 4S versions Versions earlier than V100R001C02SPC306 (BIOS V038)

RH5885 V2 8S versions Versions earlier than V100R001C02SPC306 (BIOS V062)

RH5885 V3 (E7V2) versions Versions earlier than V100R003C01SPC127 (BIOS V358)

RH5885 V3 (E7V3&E7V4) versions Versions earlier than V100R003C10SPC121 (BIOS V817)

RH5885H V3 (E7V2) versions Versions earlier than V100R003C00SPC218 (BIOS V358)

RH5885H V3 (E7V3) versions Versions earlier than V100R003C00SPC218 (BIOS V660)

RH5885H V3 (E7V4) versions Versions earlier than V100R003C10SPC120 (BIOS V817)

RH8100 V3 (E7V2&E7V3) versions Versions earlier than V100R003C00SPC229 (BIOS V698)

RH8100 V3 (E7V4) versions Versions earlier than V100R003C00SPC229 (BIOS V817)

SMC2.0 versions V500R002C00

UC Audio Recorder versions V100R001C01 V100R001C02

VP9630 versions V600R006C10

VP9660 versions V600R006C10

XH310 V3 versions Versions earlier than V100R003C00SPC706 (BIOS V399)

XH321 V3 versions Versions earlier than V100R003C00SPC706 (BIOS V399)

XH321 V5 versions Versions earlier than V100R005C00SPC501 (BIOS V095)

XH620 V3 versions Versions earlier than V100R003C00SPC706 (BIOS V399)

XH622 V3 versions Versions earlier than V100R003C00SPC706 (BIOS V399)

XH628 V3 versions Versions earlier than V100R003C00SPC706 (BIOS V399)

eSpace U2980 versions V100R001C01 V100R001C02 V100R001C10 V200R003C00

eSpace UMS versions V200R002C00

iManager NetEco versions V600R007C00 V600R007C10 V600R007C11 V600R007C12 V600R007C20 V600R007C30 V600R007C40 V600R007C50 V600R007C60 V600R008C00 V600R008C10 V600R008C20 V600R008C30

iManager NetEco 6000 versions V600R007C40 V600R007C60 V600R007C80 V600R007C90 V600R008C00");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_xref(name:"URL", value:"https://www.huawei.com/en/psirt/security-advisories/huawei-sa-20180815-01-cpu-en");

  exit(0);
}

include( "host_details.inc" );
include( "version_func.inc" );

cpe_list = make_list( "cpe:/o:huawei:_firmware" ); #no known vulnerable devices

if( ! infos = get_app_version_from_list( cpe_list:cpe_list, nofork:TRUE ) )
  exit( 0 );

cpe = infos["cpe"];
version = toupper( infos["version"] );

patch = get_kb_item( "huawei/vrp/patch" );

if( cpe =~ "^cpe:/o:huawei:_firmware" ) {
  if( version == "" || version == "" || version == "" || version == "" ||
      version == "" ) {
    report = report_fixed_ver( installed_version:version, fixed_version:"" );
    security_message( port:0, data:report );
    exit( 0 );
  }
}

exit( 99 );
