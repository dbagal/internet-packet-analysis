import re

pat = r'''GET (.*) HTTP/([0-9].[0-9])
Host: ([^\n]+)
User-Agent: ([^\n]+)
Accept: ([^\n]+)
Accept-Language: ([^\n]+)
Accept-Encoding: ([^\n]+)
Referer: ([^\n]+)
Connection: ([^\n]+)
Upgrade-Insecure-Requests: ([^\n]+)
If-Modified-Since: ([^\n]+)
If-None-Match: ([^\n]+)\nCache-Control: ([^\n]+).*'''


pat = r'(?:(?:([\w-]+):([^\n]+))\n)+'
#pat = r'Host: ([^\n]+)\nUser-Agent: ([^\n]+)\nAccept: ([^\n]+)\nAccept-Language: ([^\n]+)\nAccept-Encoding: (?:(\w+),*).*'

pat = re.compile(pat)

string = """
GET /home.html HTTP/1.1
Host: developer.mozilla.org
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.9; rv:50.0) Gecko/20100101 Firefox/50.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: https://developer.mozilla.org/testpage.html
Connection: keep-alive
Upgrade-Insecure-Requests: 1
If-Modified-Since: Mon, 18 Jul 2016 02:36:04 GMT
If-None-Match: "c561c68d0ba92bbeb8b0fff2a9199f722e3a621a"
Cache-Control: max-age=0
"""

string3 = """
Host: developer.mozilla.org
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.9; rv:50.0) Gecko/20100101 Firefox/50.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
"""

#print(string)

for grp in pat.search(string).groups():
    print(grp)

