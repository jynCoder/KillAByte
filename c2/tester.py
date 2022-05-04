import requests
import sys 

password = "Claws"
#config:
c2_url = "http://localhost:5000"
register_uri = "/register"
task_create  = "/tasks/create"

def create_task(task_type, cmd, agent_id):
    print(f"[+] Creating task {cmd} for {agent_id}")
    r = requests.post(c2_url + task_create, json = {
        "type": task_type, 
        "cmd": cmd, 
        "agent_id": agent_id
    })
    if r.status_code == 200:
        print(r.json())
    else:
        print(r.status_code)
    

if __name__ == "__main__":
    agent= sys.argv[1]
    create_task("powershell", "whoami", agent)
    #create_task("powershell", "arp", agent)
