import io
import time
import json, csv
import requests
import urllib3
import redis
import datetime
import pandas
import hashlib

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

url = "https://127.0.0.1:8834"
verify = False
access_key = "...access_key..."
secret_key = "...secret_key..."
headers = {"X-ApiKeys": f"accessKey={access_key}; secretKey={secret_key}"}
headers_ct = {"X-ApiKeys": f"accessKey={access_key}; secretKey={secret_key}", "Accept": "application/json", "Content-Type": "application/json"}

def get(dest):
  return requests.get(f"{url}/{dest}", verify = verify, headers = {"X-ApiKeys": f"accessKey={access_key}; secretKey={secret_key}"})

def post (dest, data):
  return requests.post("{}/{}".format(url, dest), verify = verify, headers = {"X-ApiKeys": f"accessKey={access_key}; secretKey={secret_key}"}, data = data)

def json_post (dest, json):
  return requests.post(f"{url}/{dest}", verify=verify, headers = {"X-ApiKeys": f"accessKey={access_key}; secretKey={secret_key}", "Accept": "application/json", "Content-Type": "application/json"}, json = json)

r_FirstSeen = redis.Redis(db=1)
r = redis.Redis()
r_Status = redis.Redis(db=2)

scans_request = get("scans?folder_id=17")
scans = scans_request.json()['scans']

for scan in scans:
  scan_id = scan['uuid']
  if (r_Status.exists(f"nessus_{scan_id}")):
    pass
  else:
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
        vulners = vulners[vulners['Plugin ID'] != 19506]
        vulners.rename(columns={'Host':'Hostname', 'Name': 'NVT Name', 'CVSS v3.0 Base Score': 'CVSS Score'}, inplace = True)
        vulners['CVSS Score'] = vulners['CVSS Score'].fillna(0)
        vulners['Solution'] = vulners['Solution'].fillna('-')
        vulners.loc[(vulners['CVSS Score'] == 0), 'Severity Score'] = 'Info'
        vulners.loc[(vulners['CVSS Score'] > 0) & (vulners['CVSS Score'] < 4), 'Severity Score'] = 'Low'
        vulners.loc[(vulners['CVSS Score'] >= 4) & (vulners['CVSS Score'] < 7), 'Severity Score'] = 'Medium'
        vulners.loc[(vulners['CVSS Score'] >= 7) & (vulners['CVSS Score'] < 9), 'Severity Score'] = 'High'
        vulners.loc[(vulners['CVSS Score'] >= 9) & (vulners['CVSS Score'] <= 10), 'Severity Score'] = 'Critical'
        vulners[['tag', 'Company']] = 'Nessus', Company
        vulners['Port'] = vulners['Port'].astype(int)
        vulners['NetWeb_type'] = 'Net'
        vulners.loc[(vulners['Plugin ID'] == 11219), 'NetWeb_type'] = 'Net'

        net_vuln = vulners[vulners['NetWeb_type'] == 'Net'].copy()
        net_vuln['ID'] = net_vuln['Hostname'].astype(str)+'|'+net_vuln['Port'].astype(str)+'|'+net_vuln['Protocol'].astype(str)+'|'+net_vuln['Synopsis'].astype(str)+'|'+net_vuln['Description'].astype(str)
        net_vuln['ID'] = net_vuln['ID'].apply(lambda x: f"nessus_{hashlib.sha256(x.encode('utf-8')).hexdigest()}")
        net_vuln['First seen'] = datetime.date.today().strftime("%Y.%m.%d")
        for id in net_vuln['ID']:
          if (r_FirstSeen.exists(id)):
            pass
          else:
            r_FirstSeen.set(id, datetime.date.today().strftime("%Y.%m.%d"))
        net_vuln['First seen'] = net_vuln['ID'].apply(lambda x, y=r_FirstSeen: y.get(x).decode("utf-8"))
        for vuln in net_vuln[['ID', 'Hostname', 'Port', 'Protocol', 'NVT Name', 'Synopsis', 'Description', 'CVSS Score', 'Severity Score', 'Solution', 'First Seen', 'tag']].to_dict(orient='records'):
          r.rpush("net", json.dumps(vuln))
'''
        web_vuln = vulners[vulners['NetWeb_type'] == 'Web'].copy()
        web_vuln.rename(columns={'Synopsis': 'Details', 'Solution': 'Recomendation'}, inplace = True)
        web_vuln['ID'] = web_vuln['Company'].astype(str)+'|'+web_vuln['Hostname'].astype(str)+'|'+web_vuln['Port'].astype(str)+'|'+web_vuln['Details'].astype(str)+'|'+web_vuln['Description'].astype(str)
        web_vuln['ID'] = web_vuln['ID'].apply(lambda x: f"nessus_{hashlib.sha256(x.encode('utf-8')).hexdigest()}")
        web_vuln['First seen'] = datetime.date.today().strftime("%Y.%m.%d")
        for id in web_vuln['ID']:
          if (r_FirstSeen.exists(id)):
            pass
          else:
            r_FirstSeen.set(id, datetime.date.today().strftime("%Y.%m.%d"))
        web_vuln['First seen'] = web_vuln['ID'].apply(lambda x, y=r_FirstSeen: y.get(x).decode("utf-8"))
        for vuln in web_vuln[['ID', 'Hostname', 'Port', 'NVT Name', 'Details', 'Description', 'CVSS Score', 'Severity Score', 'Recomendation', 'First seen', 'tag']].to_dict(orient='records'):
          r.rpush("web_nessus", json.dumps(vuln))
'''
      r_Status.set(f"nessus_{scan_id}", datetime.date.today().strftime("%Y.%m.%d"))
