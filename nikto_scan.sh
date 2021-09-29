cat "/root/urls.txt" | while read line
do
  nikto -host "${line}" -Tuning x -C all -output /root/nikto.html -Format htm
  python3 nikto_html_parser.py $1
  rm -f nikto.html
done
