###############################################################################
# OpenVAS Vulnerability Test
#
# FileZilla Server Buffer Overflow Vulnerability
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Copyright:
# Copyright (C) 2009 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.900519");
  script_version("2020-07-31T07:11:31+0000");
  script_tag(name:"last_modification", value:"2020-07-31 07:11:31 +0000 (Fri, 31 Jul 2020)");
  script_tag(name:"creation_date", value:"2009-03-23 08:26:42 +0100 (Mon, 23 Mar 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2009-0884");
  script_bugtraq_id(34006);
  script_name("FileZilla Server Buffer Overflow Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/34089");
  script_xref(name:"URL", value:"http://sourceforge.net/project/shownotes.php?release_id=665428");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Buffer overflow");
  script_dependencies("secpod_filezilla_server_detect.nasl");
  script_mandatory_keys("FileZilla/Serv/Ver");

  script_tag(name:"impact", value:"Successful exploitation will let the attacker crash the application to
  cause denial of service.");

  script_tag(name:"affected", value:"FileZilla Server versions prior to 0.9.31.");

  script_tag(name:"insight", value:"The flaw is generated due to an error in unspecified vectors while
  handling SSL/TLS packets.");

  script_tag(name:"solution", value:"Upgrade to FileZilla Server version 0.9.31.");

  script_tag(name:"summary", value:"This host is running FileZilla Server and is prone to buffer
  overflow vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

filezillaVer = get_kb_item("FileZilla/Serv/Ver");
if(!filezillaVer){
  exit(0);
}

if(version_is_less(version:filezillaVer, test_version:"0.9.31")){
  report = report_fixed_ver(installed_version:filezillaVer, fixed_version:"0.9.31");
  security_message(port: 0, data: report);
}
