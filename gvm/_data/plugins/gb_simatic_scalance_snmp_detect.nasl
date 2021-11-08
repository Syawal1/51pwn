###############################################################################
# OpenVAS Vulnerability Test
#
# Siemens SIMATIC SCALANCE Device Detection (SNMP)
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.140748");
  script_version("2020-03-26T08:48:45+0000");
  script_tag(name:"last_modification", value:"2020-03-26 08:48:45 +0000 (Thu, 26 Mar 2020)");
  script_tag(name:"creation_date", value:"2018-02-05 15:43:30 +0700 (Mon, 05 Feb 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Siemens SIMATIC SCALANCE Device Detection (SNMP)");

  script_tag(name:"summary", value:"This script performs SNMP based detection of Siemens SIMATIC SCALANCE
  devices.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_snmp_sysdesc.nasl");
  script_require_udp_ports("Services/udp/snmp", 161);
  script_mandatory_keys("SNMP/sysdesc/available");

  script_xref(name:"URL", value:"https://new.siemens.com/global/en/products/automation/industrial-communication/scalance.html");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("snmp_func.inc");

port = snmp_get_port(default: 161);

sysdesc = snmp_get_sysdesc(port: port);
if (!sysdesc)
  exit(0);

# Siemens, SIMATIC NET, SCALANCE M876-4 EU, 6GK5 876-4AA00-2BA2, HW: Version 1, FW: Version V04.02.03, SVPJ5127948
# Siemens, SIMATIC NET, Scalance S612, 6GK56120BA102AA3, HW: Version 2, FW: Version V03.00.00.01_01.00.00.01, VPCO544487
if (egrep(string: sysdesc, pattern: "Siemens, SIMATIC NET, SCALANCE", icase: TRUE)) {
  set_kb_item(name: "simatic_scalance/detected", value: TRUE);

  sp = split(sysdesc, sep: ",", keep: FALSE);

  # Model
  if (!isnull(sp[2])) {
    mo = eregmatch(pattern: "scalance (.*)", string: tolower(sp[2]));
    if (!isnull(mo[1])) {
      model = mo[1];
      set_kb_item(name: "simatic_scalance/model", value: model);
    }
  }

  # Version
  if (!isnull(sp[5])) {
    vers = eregmatch(pattern: "V([0-9.]+)", string: sp[5]);
    if (!isnull(vers[1])) {
      version = vers[1];
      set_kb_item(name: "simatic_scalance/version", value: version);
    }
  }

  # Module
  if (!isnull(sp[3])) {
    modu = eregmatch(pattern: "^ (.*)", string: sp[3]);
    if (!isnull(modu[1])) {
      module = modu[1];
      extra += 'Module:      ' + module + '\n';
      set_kb_item(name: "simatic_scalance/module", value: module);
    }
  }

  # HW Version
  if (!isnull(sp[4])) {
    hw = eregmatch(pattern: "HW: Version ([0-9]+)", string: sp[4]);
    if (!isnull(hw[1])) {
      hw_version = hw[1];
      extra += 'HW Version:  ' + hw_version + '\n';
      set_kb_item(name: "simatic_scalance/hw_version", value: hw_version);
    }
  }

  # CPE
  if (model) {
    cpe_model = tolower(ereg_replace(pattern: " ", string: model, replace: "_"));

    app_cpe = build_cpe(value: version, exp: "^([0-9.]+)",
                        base: "cpe:/a:siemens:simatic_" + cpe_model + ":");
    if (!app_cpe)
      app_cpe = "cpe:/a:siemens:simatic_" + cpe_model;

    os_cpe = build_cpe(value: version, exp: "^([0-9.]+)",
                       base: "cpe:/o:siemens:simatic_" + cpe_model + "_firmware:");
    if (!os_cpe)
      os_cpe = "cpe:/o:siemens:simatic_" + cpe_model + "_firmware";
  }
  else {
    if (version) {
      app_cpe = "cpe:/a:siemens:simatic_scalance:" + version;
      os_cpe = "cpe:/o:siemens:simatic_scalance_firmware:" + version;
    }
    else {
      app_cpe = "cpe:/a:siemens:simatic_scalance";
      os_cpe = "cpe:/o:siemens:simatic_scalance_firmware";
    }
  }

  register_product(cpe: app_cpe, location: port + "/udp", port: port, service: "snmp", proto: "udp");
  register_product(cpe: os_cpe, location: port + "/udp", port: port, service: "snmp", proto: "udp");

  register_and_report_os(os: "Siemens SIMATIC S7 SCALANCE Firmware", version: version, cpe: os_cpe,
                       desc: "Siemens SIMATIC SCALANCE Device Detection (SNMP)", runs_key: "unixoide");

  log_message(data: build_detection_report(app: "Siemens SIMATIC SCALANCE " + model, version: version,
                                           install: port + "/udp", cpe: app_cpe, concluded: sysdesc,
                                           extra: extra),
              port: port, proto: "udp");
  exit(0);
}

exit(0);

