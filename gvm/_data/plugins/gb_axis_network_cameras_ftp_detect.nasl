###############################################################################
# OpenVAS Vulnerability Test
#
# Axis Camera Detection (FTP)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810933");
  script_version("2020-08-24T08:40:10+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2017-04-20 13:57:40 +0530 (Thu, 20 Apr 2017)");

  script_name("Axis Camera Detection (FTP)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp/axis/network_camera/detected");

  script_tag(name:"summary", value:"FTP based detection of Axis network cameras.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("ftp_func.inc");
include("misc_func.inc");
include("port_service_func.inc");
include("host_details.inc");

port = ftp_get_port(default:21);
banner = ftp_get_banner(port:port);
if (!banner || banner !~ "220[- ](AXIS|Axis).*Network Camera")
  exit(0);

set_kb_item(name:"axis/camera/detected", value:TRUE);

version = "unknown";
model = "unknown";

mod = eregmatch(pattern:"220 (AXIS|Axis) ([^ ]+) ", string:banner);
if (!isnull(mod[2]))
  model = mod[2];

vers = eregmatch(pattern:"Network Camera ([0-9.]+)", string:banner);
if (!isnull(vers[1]))
  version = vers[1];

if (model != "unknown") {
  os_name = "Axis " + model + " Network Camera Firmware";
  hw_name = "Axis " + model + " Network Camera";
  os_cpe = build_cpe(value:version, exp:"^([0-9.]+)", base:"cpe:/o:axis:" + tolower(model) + "_firmware:");
  if (!os_cpe)
    os_cpe = "cpe:/o:axis:" + tolower(model) + "_firmware";

  hw_cpe = "cpe:/h:axis:" + tolower(model);
} else {
  os_name = "Axis Unknown Model Network Camera Firmware";
  hw_name = "Axis Unknown Model Network Camera";
  os_cpe = build_cpe(value:version, exp:"^([0-9.]+)", base:"cpe:/o:axis:network_camera_firmware:");
  if (!os_cpe)
    os_cpe = "cpe:/o:axis:network_camera_firmware";

  hw_cpe = "cpe:/h:axis:network_camera";
}

register_and_report_os(os:os_name, cpe:os_cpe, desc:"Axis Camera Detection (FTP)", runs_key:"unixoide");

register_product(cpe:os_cpe, location:"/", port:port, service:"ftp");
register_product(cpe:hw_cpe, location:"/", port:port, service:"ftp");

report  = build_detection_report(app: os_name, version: version, install: "/", cpe: os_cpe, concluded: banner);
report += '\n\n';
report += build_detection_report(app: hw_name, skip_version: TRUE, install: "/", cpe: hw_cpe);

log_message(port: port, data: report);

exit(0);
