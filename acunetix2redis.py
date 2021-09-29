import json
import requests
import time
import hashlib
import sys
import redis
import datetime


requests.packages.urllib3.disable_warnings()

tarurl = "https://127.0.0.1:3443/"
apikey = "..."
headers = {'content-type': 'application/json', 'X-Auth': apikey}

scan_profiles_list = {'full_scan':'11111111-1111-1111-1111-111111111111'}

r_FirstSeen = redis.Redis(db=1)
r = redis.Redis()
r_Status = redis.Redis(db=2)

def get_results(location):
  results = json.loads(requests.get(tarurl+str(location)+'/results', headers=headers, verify=False).text)
  for result in results['results']:
    if (r_Status.exists(f"{location}|{result['result_id']}")):
      pass
    else:
      vulns = requests.get(tarurl+str(location)+f'/results/{result["result_id"]}/vulnerabilities', headers=headers, verify=False)
      for vuln in json.loads(vulns.text)['vulnerabilities']:
        new_dict = {}
        data = json.loads(requests.get(tarurl+str(location)+f'/results/{result["result_id"]}/vulnerabilities/{vuln["vuln_id"]}', headers=headers, verify=False).text)
        NVT_id = f"{data['affects_detail']}|{data['affects_url']}|{data['vt_name']}|{data['description']}|{data['details']}"
        q1_hash = hashlib.sha256(NVT_id.encode('utf-8')).hexdigest()
        new_dict['ID'] = f"acunetix_{q1_hash}"
        new_dict['tag'] = "Acunetix"
        new_dict['Affects detail'] = data['affects_detail']
        new_dict['Affects URL'] = data['affects_url']
        new_dict['CVSS3'] = data['cvss3']
        new_dict['CVSS Score'] = data['cvss_score']
        new_dict['Description'] = data['description']
        new_dict['Details'] = data['details']
        new_dict['Highlights'] = data['highlights']
        new_dict['Impact'] = data['impact']
        new_dict['Recommendation'] = data['recommendation']
        new_dict['Severity'] = data['severity']
        new_dict['NVT Name'] = data['vt_name']
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
        if (r_FirstSeen.exists(new_dict['ID'])):
          new_dict['First seen'] = r_FirstSeen.get(new_dict['ID']).decode("utf-8")
        else:
          r_FirstSeen.set(new_dict['ID'], datetime.date.today().strftime("%Y.%m.%d"))
          new_dict['First seen'] = r_FirstSeen.get(new_dict['ID']).decode("utf-8")
        r.rpush("acunetix", json.dumps(new_dict))
    r_Status.set(f"{location}|{result['result_id']}", datetime.date.today().strftime("%Y.%m.%d"))

def addtask(url):
  data = {'address': url, 'description': url, 'critically': '10'}
  try:
    response = requests.post(tarurl+'/api/v1/targets', data=json.dumps(data), headers=headers, timeout=30, verify=False)
    result = json.loads(response.content)
    return result['target_id']
  except Exception as e:
    print(str(e))
    return

def startscan(url):
  targets = getscan()
  if url in targets:
    return "repeat"
  else:
    target_id = addtask(url)
    data = {"target_id":target_id,"profile_id":"11111111-1111-1111-1111-111111111111","schedule": {"disable": False,"start_date":None,"time_sensitive": False}}
    try:
      response = requests.post(tarurl+"/api/v1/scans",data=json.dumps(data),headers=headers,timeout=30,verify=False)
      result = json.loads(response.content)
      return result['target_id']
    except Exception as e:
      print(str(e))
      return

def getstatus(location):
  try:
    response = requests.get(tarurl+str(location),headers=headers,timeout=30,verify=False)
    result = json.loads(response.content)
    status = result['current_session']['status']
    return result['current_session']['status']
  except Exception as e:
    print(str(e))
    return

def delete_scan(scan_id):
  try:
    response = requests.delete(tarurl+"/api/v1/scans/"+str(scan_id),headers=headers,timeout=30,verify=False)
    if response.status_code == "204":
      return True
    else:
      return False
  except Exception as e:
    print(str(e))
    return

def delete_target(target_id):
  try:
    response = requests.delete(tarurl+"/api/v1/targets/"+str(target_id),headers=headers,timeout=30,verify=False)
  except Exception as e:
    print(str(e))
    return

def stop_scan(scan_id):
  try:
    response = requests.post(tarurl+"/api/v1/scans/"+str(scan_id+"/abort"),headers=headers,timeout=30,verify=False)
    if response.status_code == "204":
      return True
    else:
      return False
  except Exception as e:
    print(str(e))
    return

def getreports(scan_id):
  data = {"template_id":"11111111-1111-1111-1111-111111111111","source":{"list_type":"scans","id_list":[scan_id]}}
  try:
    response = requests.post(tarurl+"/api/v1/reports",data=json.dumps(data),headers=headers,timeout=30,verify=False)
    result = response.headers
    report = result['Location'].replace('/api/v1/reports/','/reports/download/')
    return tarurl.rstrip('/')+report
  except Exception as e:
    print(str(e))
    return
  finally:
    delete_scan(scan_id)

def generated_report(scan_id,target):
  data = {"template_id": "21111111-1111-1111-1111-111111111111","source": {"list_type": "scans", "id_list":[scan_id]}}
  try:
    response = requests.post(tarurl + "/api/v1/reports", data=json.dumps(data), headers=headers, verify=False)
    report_url = tarurl.strip('/') + response.headers['Location']
    requests.get(str(report_url),headers=headers, verify=False)
    while True:
      report = get_report(response.headers['Location'])
      if not report:
        time.sleep(5)
      elif report:
        break
    if(not os.path.exists("reports")):
      os.mkdir("reports")
    report = requests.get(tarurl + report,headers=headers, verify=False,timeout=120)
    filename = str(target.strip('/').split('://')[1]).replace('.','_').replace('/','-')
    file = "reports/" + filename + "%s.xml" % time.strftime("%Y-%m-%d-%H-%M", time.localtime(time.time()))
    with open(file, "wb") as f:
      f.write(report.content)
    print("[INFO] %s report have %s.xml is generated successfully" % (target,filename))
  except Exception as e:
    raise e
  finally:
    delete_report(response.headers['Location'])

def get_report(reportid):
  res = requests.get(url=tarurl + reportid, timeout=10, verify=False, headers=headers)
  try:
    report_url = res.json()['download'][0]
    return report_url
  except Exception as e:
    return False

def config():
  for target_id in targets_dict:
    time.sleep(1)
    data = {"scan_speed": "slow"}
    res = requests.patch(tarurl+"/api/v1/targets/"+str(target_id)+"/configuration", data=json.dumps(data), headers=headers, timeout=120, verify=False)

    data = {"target_id":target_id,"profile_id":"11111111-1111-1111-1111-111111111111","schedule": {"disable": False,"start_date":None,"time_sensitive": False}}
    try:
      response = requests.post(tarurl+"/api/v1/scans",data=json.dumps(data),headers=headers,timeout=30,verify=False)
      targets_dict[target_id] = response.headers['Location']
    except Exception as e:
      print(str(e))
      return

def fin():
  while targets_dict:
    completed_id = []
    for id in targets_dict:
      status = getstatus(targets_dict[id])
      if status == 'completed':
        get_results(targets_dict[id])
        delete_target(id)
        completed_id.append(id)
      elif status == 'processing' or status == 'scheduled' or status == 'queued':
        time.sleep(0.5)
      else:
        completed_id.append(id)
    for i in completed_id:
      del targets_dict[i]

def getscan():
  targets = []
  try:
    response = requests.get(tarurl+"/api/v1/scans",headers=headers,timeout=30,verify=False)
    results = json.loads(response.content)
    for result in results['scans']:
      targets.append(result['target']['address'])
      print(result['scan_id'], result['target']['address'], getstatus(result['scan_id']), result['target_id'])
    return list(set(targets))
  except Exception as e:
    raise e

if __name__ == '__main__':
  company = sys.argv[1]
  targets_dict = {}
  f = open(f"/root/urls.txt")
  for url in f:
    targets_dict[addtask(url1)] = url1
  config()
  fin()
