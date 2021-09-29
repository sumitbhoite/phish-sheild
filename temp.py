import requests
res = requests.post('http://127.0.0.1:5000/post', json={"URL":"https://www.google.com/"})
if res.ok:
    print(res.json())