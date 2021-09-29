from bs4 import BeautifulSoup as BS
import hashlib
import uuid
import json
import redis
import datetime
import sys

f = open("/root/nikto.html", "r")
data = f.read()
soup = BS(data, "html.parser")
b = {}
dup_data = []

r_FirstSeen = redis.Redis(db=1)
r = redis.Redis()
r_Status = redis.Redis(db=2)

a = {'Description': '', 'Target IP': '', 'Hostname': '', 'Port': '', 'URI': '', 'HTTP Method': '', 'Test Links': '', 'OSVDB Entires': ''}
for link in soup.find_all(class_='dataTable'):
  table_row = link.find_all('tr')
  for tr in table_row:
    for tt in tr.find_all(class_='column-head'):
      if tt.text == "Description":
        for ttt in tr.find_all('td'):
          for tttt in ttt.find_all('b'):
            del tttt
        a['Description'] = ttt.text
      elif tt.text == "Target IP":
        for ttt in tr.find_all('td'):
          for tttt in ttt.find_all('b'):
            del tttt
        a['Target IP'] = ttt.text
      elif tt.text == "Target hostname":
        for ttt in tr.find_all('td'):
          for tttt in ttt.find_all('b'):
            del tttt
        a['Hostname'] = ttt.text
      elif tt.text == "Target Port":
        for ttt in tr.find_all('td'):
          for tttt in ttt.find_all('b'):
            del tttt
        a['Port'] = ttt.text
      elif tt.text == "URI":
        for ttt in tr.find_all('td'):
          for tttt in ttt.find_all('b'):
            del tttt
        a['URI'] = ttt.text
      elif tt.text == "HTTP Method":
        for ttt in tr.find_all('td'):
          for tttt in ttt.find_all('b'):
            del tttt
        a['HTTP Method'] = ttt.text
      elif tt.text == "Test Links":
        for ttt in tr.find_all('td'):
          for tttt in ttt.find_all('b'):
            del tttt
        a['Test Links'] = ttt.text
      elif tt.text == "OSVDB Entries":
        for ttt in tr.find_all('td'):
          for tttt in ttt.find_all('b'):
            del tttt
        a['OSVDB Entires'] = ttt.text
  if (a['Description'] != '' and a['Hostname'] != '' and a['Port'] != ''):
    q1 = json.dumps(a)
    q1_hash = hashlib.sha256(q1.encode('utf-8')).hexdigest()
  else:
    q1 = ''
  if (a['Description'] != '' and a['Hostname'] != '' and a['Port'] != '' and q1_hash not in dup_data):
    dup_data.append(q1_hash)
    a['ID'] = f"nikto_{q1_hash}"
    if r_FirstSeen.exists(a['ID']):
      a['First seen'] = r_FirstSeen.get(a['ID']).decode('utf-8')
    else:
      r_FirstSeen.set(a['ID'], datetime.date.today().strftime("%Y.%m.%d"))
      a['First seen'] = r_FirstSeen.get(a['ID']).decode('utf-8')
    r.rpush("nikto", json.dumps(a))
