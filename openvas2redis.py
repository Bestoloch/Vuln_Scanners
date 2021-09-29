from gvm.connections import UnixSocketConnection, TLSConnection, GvmConnection
from gvm.protocols.gmp import Gmp
from gvm.transforms import EtreeTransform
from gvm.xml import pretty_print
import xml.etree.ElementTree as ET
import xmltodict, json, xmljson, csv
from lxml.etree import fromstring
import untangle
import base64
from os import path, listdir
import configparser
import subprocess
import redis
import datetime
import hashlib
import sys

connection = TLSConnection(hostname='127.0.0.1', port=9390, timeout=120)
transform = EtreeTransform()
csv.field_size_limit(sys.maxsize)

def exportReports():
  r_FirstSeen = redis.Redis(db=1)
  r = redis.Redis()
  r_Status = redis.Redis(db=2)

  with Gmp(connection) as gmp:
    gmp.authenticate('...', '...')
    report_formats = ET.fromstring(gmp.get_report_formats())
    reportFormatID = ""
    for report in report_formats:
      for format in report:
        if ("CSV result list." in str(format.text)):
          reportFormatID = report.attrib.get('id')
    getReports = []
    all_reports = ET.fromstring(gmp.get_reports(filter_string='status="Done"'))
    for report in all_reports:
      if (report.tag == 'report'):
        for one_report in report:
          if (one_report.tag == 'report'):
            if (r_Status.exists(report.attrib.get('id'))):
              pass
            else:
              getReports.append(report.attrib.get('id'))
    print(getReports)

    for reportID in getReports:
      print(reportID)
      reportcsv = gmp.get_report(reportID,report_format_id=reportFormatID,filter_string='apply_overrides=0 min_qod=60 severity>4', ignore_pagination=True,details=True)
      obj = untangle.parse(reportcsv)
      resultID = obj.get_reports_response.report['id']
      base64CVSData = obj.get_reports_response.report.cdata
      data = str(base64.b64decode(base64CVSData),"utf-8")
      f = open("/root/openVAS.csv", "w")
      f.write(data)
      f.close()
      new_dict = {}
      with open("/root/scan_files/openVAS/csv.csv", "r") as csvFile:
        csvReader = csv.DictReader(csvFile)
        for csvRow in csvReader:
          NVT_id = f"{csvRow['IP']}|{csvRow['Port']}|{csvRow['Port Protocol']}|{csvRow['NVT Name']}|{csvRow['Specific Result']}|{csvRow['Summary']}"
          q1_hash = hashlib.sha256(NVT_id.encode('utf-8')).hexdigest()
          new_dict['ID'] = f"openvas_{q1_hash}"
          new_dict['tag'] = 'OpenVAS'
          new_dict['Host IP'] = csvRow['IP']
          new_dict['Hostname'] = csvRow['Hostname']
          new_dict['Port'] = csvRow['Port']
          new_dict['Protocol'] = csvRow['Port Protocol']
          new_dict['NVT Name'] = csvRow['NVT Name']
          new_dict['Severity'] = csvRow['Severity']
          new_dict['CVSS Score'] = float(csvRow['CVSS'])
          if (new_dict['CVSS Score'] == 0):
            new_dict['Severity Score'] = "Info"
          elif (new_dict['CVSS Score'] > 0) and (new_dict['CVSS Score'] < 4):
            new_dict['Severity Score'] = "Low"
          elif (new_dict['CVSS Score'] >= 4) and (new_dict['CVSS Score'] < 7):
            new_dict['Severity Score'] = "Medium"
          elif (new_dict['CVSS Score'] >= 7) and (new_dict['CVSS Score'] < 9):
            new_dict['Severity Score'] = "High"
          elif (new_dict['CVSS Score'] >= 9) and (new_dict['CVSS Score'] <= 10):
            new_dict['Severity Score'] = "Critical"
          else:
            new_dict['Severity Score'] = "Info"
          new_dict['Synopsis'] = csvRow['Summary']
          new_dict['Description'] = csvRow['Specific Result']
          new_dict['Solution'] = csvRow['Solution']
          if (r_FirstSeen.exists(new_dict['ID'])):
            new_dict['First seen'] = r_FirstSeen.get(new_dict['ID']).decode("utf-8")
          else:
            r_FirstSeen.set(new_dict['ID'], datetime.date.today().strftime("%Y.%m.%d"))
            new_dict['First seen'] = r_FirstSeen.get(new_dict['ID']).decode("utf-8")
          r.rpush("openvas", json.dumps(new_dict))
      r_Status.set(reportID, datetime.date.today().strftime("%Y.%m.%d"))
