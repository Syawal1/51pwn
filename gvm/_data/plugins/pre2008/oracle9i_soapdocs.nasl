###############################################################################
# OpenVAS Vulnerability Test
#
# Oracle 9iAS access to SOAP documentation
#
# Authors:
# Javier Fernandez-Sanguino <jfs@computer.org>
#
# Copyright:
# Copyright (C) 2003 Javier Fernandez-Sanguino
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
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

CPE = "cpe:/a:oracle:http_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11223");
  script_version("2020-05-08T08:34:44+0000");
  script_tag(name:"last_modification", value:"2020-05-08 08:34:44 +0000 (Fri, 08 May 2020)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Oracle 9iAS access to SOAP documentation");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2003 Javier Fernandez-Sanguino");
  script_family("Web application abuses");
  script_dependencies("gb_oracle_app_server_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("oracle/http_server/detected");

  script_xref(name:"URL", value:"http://otn.oracle.com/deploy/security/pdf/ias_soap_alert.pdf");
  script_xref(name:"URL", value:"http://www.cert.org/advisories/CA-2002-08.html");
  script_xref(name:"URL", value:"http://www.nextgenss.com/papers/hpoas.pdf");

  script_tag(name:"solution", value:"Remove the 'soapdocs' alias from the Oracle 9iAS http.conf:

  Alias /soapdocs/ $ORACLE_HOME/soap/docs/

  Note that the default installation of Oracle 9iAS 1.0.2.2 does not
  seem to suffer this issue.");

  script_tag(name:"summary", value:"In a default installation of Oracle 9iAS, it is possible to
  access SOAP documentation. These files might be useful for an attacker
  to determine what application server is being used.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"Workaround");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!get_app_location(cpe:CPE, port:port))
  exit(0);

# Somebody needs to parse the Oracle documentation and put more files in
# these are just some examples out there.
documents = make_list(
"ReleaseNotes.html",
"docs/apiDocs/packages.html",
"docs/apiDocs/org.apache.soap.util.xml.XMISerializer.html" );

# This one is too big to be retrieved
# "docs/apiDocs/AllNames.html";

report = 'The following documentation file can be retrieved remotely:\n';
VULN   = FALSE;

foreach document( documents ) {

  url = "/soapdocs/" + document;
  req = http_get( item:url, port:port );
  r = http_keepalive_send_recv( port:port, data:req, bodyonly:TRUE );
  if( isnull( r ) ) exit( 0 );

  if( "SOAP" >< r || "Index of" >< r || "Package Index" >< r || "Generated by javadoc"  >< r ) {
    report += '\n' + http_report_vuln_url( port:port, url:url, url_only:TRUE );
  }
}

if( VULN ) {
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );

# TODO:
# this should also check for some information in the documentation and retrieve the precise version.
# Sample:
# ReleasesNotes.html has <center>iAS v1.X.X.X</center>  which indicates the Oracle iAS version