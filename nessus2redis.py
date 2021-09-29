import io
import json, csv
import requests
import urllib3
import tempfile
import time
import os
import redis
import datetime
import socket
import xmltodict
import pandas
import hashlib
from lxml import etree

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

url = "https://127.0.0.1:8834"
verify = False
access_key = "..."
secret_key = "..."

def get(dest):
  return requests.get(f"{url}/{dest}", verify = verify, headers = {"X-ApiKeys": f"accessKey={access_key}; secretKey={secret_key}"})

def post (dest, data):
  return requests.post(f"{url}/{dest}", verify = verify, headers = {"X-ApiKeys": f"accessKey={access_key}; secretKey={secret_key}"}, data = data)

def json_post (dest, json):
  return requests.post(f"{url}/{dest}", verify=verify, headers = {"X-ApiKeys": f"accessKey={access_key}; secretKey={secret_key}", "Accept": "application/json", "Content-Type": "application/json"}, json = json)

r_FirstSeen = redis.Redis(db=1)
r = redis.Redis()
r_Status = redis.Redis(db=2)

scans_request = get("scans")
scans = scans_request.json()['scans']

for scan in scans:
  scan_name = scan['name']
  if scan['status'] == 'completed':
    data = {
      "format":"csv",
      "reportContents": {
        "csvColumns": {
          "id": True,
          "cve": True,
          "cvss": False,
          "risk": False,
          "hostname": True,
          "protocol": True,
          "port": True,
          "plugin_name": True,
          "cvss3_base_score": True,
          "description": True,
          "synopsis": True,
          "solution": True,
          "see_also": False,
          "plugin_output": False
        }
      }
    }
    resp = json_post(f"scans/{scan['id']}/export", data)
    export_token = json.loads(resp.text)['file']
    resp_status = get(f"scans/{scan['id']}/export/{export_token}/status")
    status = json.loads(resp_status.text)['status']
    while (status != "ready"):
      time.sleep(0.5)
      resp_status = get(f"scans/{scan['id']}/export/{export_token}/status")
      status = json.loads(resp_status.text)['status']
    if status == "ready":
      resp_nessus = get(f"scans/{scan['id']}/export/{export_token}/download")
      vulners = pandas.read_csv(io.StringIO(resp_nessus.text), delimiter=',')
      vuln_dict = vulners.to_dict(orient='records')
      for vuln in vuln_dict:
        new_dict = {}
        new_dict['Hostname'] = vuln['Host']
        new_dict['Description'] = vuln['Description']
        new_dict['NVT Name'] = vuln['Name']
        new_dict['Port'] = int(vuln['Port'])
        new_dict['tag'] = 'Nessus'
        if (pandas.isna(vuln['CVSS v3.0 Base Score'])):
          new_dict['CVSS Score'] = 0
        else:
          new_dict['CVSS Score'] = int(vuln['CVSS v3.0 Base Score'])
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
        new_dict['Protocol'] = vuln['Protocol']
        new_dict['Synopsis'] = vuln['Synopsis']
        if (pandas.isna(vuln['Solution'])):
          new_dict['Solution'] = "-"
        else:
          new_dict['Solution'] = vuln['Solution']
        NVT_id = f"{new_dict['Hostname']}|{new_dict['Port']}|{new_dict['Protocol']}|{new_dict['Synopsis']}|{new_dict['Description']}"
        q1_hash = hashlib.sha256(NVT_id.encode('utf-8')).hexdigest()
        new_dict['ID'] = f"nessus_{q1_hash}"
        if (r_FirstSeen.exists(new_dict['ID'])):
          new_dict['First seen'] = r_FirstSeen.get(new_dict['ID']).decode("utf-8")
        else:
          r_FirstSeen.set(new_dict['ID'], datetime.date.today().strftime("%Y.%m.%d"))
          new_dict['First seen'] = r_FirstSeen.get(new_dict['ID']).decode("utf-8")
        r.rpush("nessus", json.dumps(new_dict)+"\n")
