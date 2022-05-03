# HTTP GET/POST

### Usage:
`http.exe (fqdn) (port) (uri) (use_tls) (get/post = 0/1) (data)`

### GET Example:
`.\bin\http.exe 127.0.0.1 5000 /tasks/list 0 0 0`

### POST Example:
`.\bin\http.exe 127.0.0.1 5000 /tasks/create 0 1 "{'type': 'powershell', 'cmd': 'whoami', 'agent_id': '0'}"`

### Notes:
- 0/1 for GET/POST
- 0/1 for HTTP/HTTPS
- Enter JSON data with single quotes, the quotes are parsed in the function