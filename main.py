from typing import Union, Optional, List
from fastapi import FastAPI ,File, UploadFile,Depends, Response, status,HTTPException
from datetime import datetime
from fastapi import security
from pydantic import BaseModel
from pydantic.networks import IPvAnyAddress
import google.generativeai as genai
import requests
from bs4 import BeautifulSoup
import subprocess
from pinecone import Pinecone
import re
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.runnables import Runnable
import boto3
from botocore.exceptions import ClientError
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from langchain.agents import Tool, initialize_agent
from langchain.chat_models import ChatOpenAI
from langchain.prompts import MessagesPlaceholder
from langchain.schema import HumanMessage
from langchain_core.messages import ToolMessage
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from langchain.tools import BaseTool
from typing import Any, Dict
import subprocess
import requests
import os
import boto3
import paramiko
import smtplib
from collections import deque
from fastapi.middleware.cors import CORSMiddleware
from pinecone_plugins.assistant.models.chat import Message
import jwt
import redis
from supabase import create_client, Client
from urllib.parse import urlencode
import json
import hashlib
from requests.auth import HTTPBasicAuth
from fastapi import Depends
import uuid
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jwt import PyJWTError
from typing import Annotated
import asyncio
from sse_starlette.sse import EventSourceResponse
from typing import AsyncGenerator

from worker import worker_loop

async def worker_lifespan(app: FastAPI):
    """Start multiple worker threads when application starts"""
    import threading
    import os
    
    # Safe parsing of WORKER_COUNT with fallback and limits
    try:
        worker_count = int(os.getenv("WORKER_COUNT", "1"))
    except (TypeError, ValueError):
        worker_count = 1
    
    if worker_count < 1:
        worker_count = 1
    worker_count = min(worker_count, 64)  # cap to avoid runaway thread creation
    
    threads = []
    for i in range(worker_count):
        thread = threading.Thread(target=worker_loop, daemon=True, name=f"Worker-{i+1}")
        thread.start()
        threads.append(thread)
    
    # Store threads in app state for potential graceful shutdown
    app.state.worker_threads = threads
    
    yield

app = FastAPI(lifespan=worker_lifespan)
security = HTTPBearer()
from langchain_google_genai import ChatGoogleGenerativeAI
from openai import OpenAI
import os
from dotenv import load_dotenv
import getpass
from langchain_core.tools import tool
from langchain.agents import initialize_agent, Tool
from langchain.memory import ConversationBufferMemory
from langchain.schema import HumanMessage
from tavily import TavilyClient
from langchain_core.output_parsers import JsonOutputParser

load_dotenv()
genai.configure(api_key=os.getenv('Gemini_Api_Key'))
pc = Pinecone(api_key=os.getenv('Pinecone_Api_Key'))
# Ensure your VertexAI credentials are configured
url: str = os.getenv("SUPABASE_URL")
key: str = os.getenv("SUPABASE_KEY")

from langchain_google_vertexai import ChatVertexAI
supabase: Client = create_client(url, key)
session = boto3.Session(
    aws_access_key_id=os.getenv('access_key'),
    aws_secret_access_key=os.getenv('secrete_access'),
    region_name='ap-south-1'
)

from langchain.chat_models import init_chat_model
model = init_chat_model("mistral-large-latest", model_provider="mistralai")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"], # Specific origin
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
r = redis.Redis(host='localhost', port=6379, db=0)

clerk_public_key = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxFwlegGWXS3gVaKyX/Ck
pwRENl+blwEkCtqfnjjHSV5TScDHwum4uQFcAW6VgyESbeA6tDI5VF72ZRcJ58yE
m1uJLLDQNDrG0BAa2jYAgcRZeQcJklXp+E5C7kv+wQh/19/24/ze09l9N2jIvhKk
OCICAoJ/AtnsvsYRhi74z+HVzEZZmVtofeHxZBlBU3XX0v0u9gYnqsm550Ndk/K3
fHY1QOV8mAYKMrqhrpbC4dsGDn9WGta0h003zrHrMauA9mvnGBgIdHMXZiYWjC7M
mkew+iKms63o1+K6p16OGX3DR+WYnjCWOf6SxsTWOxTCBzxow+m693Afg3stBLR3
ZQIDAQAB
-----END PUBLIC KEY-----"""

system_prompt='''your an expert ai engineer and can write ansible playbooks for aws
return all code in the following format
<shell_commands>
commands to install ansible modules (this only includes ansible modules dont install other packages) ansible-galaxy commands
</shell_commands>
<inventory_file>
this contains the inventory file
</inventory_file>
<playbook>
this contains the playbook
</playbook>
<playbook_run_command>
contains the command to run the playbook (use .ini extension for inventory file and .yml extension for playbook file)
</playbook_run_command>


- Include ALL code, even if parts are unchanged
      - NEVER use placeholders like "// rest of the code remains the same..." or "<- leave original code here ->"
      - ALWAYS show the complete, up-to-date file contents when updating files
      - Avoid any form of truncation or summarization
      - AWS access keys and secrete access keys are in a file called vars.yml use that to authenticate
      - key file will be in the same directory with name key.pem
      - playbook file will be in the same directory with name playbook.yml
      - inventory file will be in the same directory with name inventory_file
      - dont make any mistakes in the code make sure the syntax is correct and spacing is correct
      - dont use any undefined variables
      - variables in vars.yml file include aws_access_key, aws_secret_key, aws_region, everything is default value
      - mention file extensions in  <playbook_run_command> command
      - dont create a recursive playbook where for aws_region make sure not to cause circular dependency
      - use inventory_file.ini as inventory file and mention inventory_file.ini in playbook_command file 
      - if that module is not installed install it using ansible galaxy in the <shell_commands> section
      - dont use the wrong module for the wrong task
      - access_key,secret_key and region are in vars.yml file include it in the playbook
        - dont use any interactive commands
        - use this for amis": [
    {
      "amazon_linux": "ami-00bb6a80f01f03502",
      "ubuntu": "ami-00bb6a80f01f03502",
      "rhel": "ami-02ddb77f8f93ca4ca",
      "suse": "ami-0da723ce59d9e80ab",
      "windows_server": "ami-05a00967f06885a63"
    }
  ],
  "vpc_id":"vpc-0b0f2397039aefca8",
  "subnet_id":"subnet-028fb8a226cdc8c98",
  "key_name":"latest" for ami ids key name vpc id etc
   - make contents inside <inventory_file> tag blank if its not needed
   - dont use  associate_public_ip_address: yes in the playbook
   - generate correct commands to install the modules which are required by the task
   - dont use any interactive commands
   - ansible modules for aws include Community.Aws , amazon.aws · ansible.builtin · ansible.netcommon · ansible.posix · ansible.utils · ansible.windows · arista.eos · awx.awx 
   - just do what is told and dont add any tests to the playbook
   - dont use any interactive commands
   - dont add any extra steps to the playbook
   - inventory file example
            [(any_name)]
            ip_address of the machine
            [(any_name):vars]
            ansible_ssh_user=(depends on os)
            ansible_ssh_private_key_file=key.pem (this remains the same)
    - default user for ubuntu is ubuntu and for amazon linux is ec2-user
    - dont use variables if its not defined
    -  variables defined in vars.yml file are aws_access_key, aws_secret_key, aws_region
        '''

amazon_context={
  "amis": [
    {
      "amazon_linux": "ami-00bb6a80f01f03502",
      "ubuntu": "ami-00bb6a80f01f03502",
      "rhel": "ami-02ddb77f8f93ca4ca",
      "suse": "ami-0da723ce59d9e80ab",
      "windows_server": "ami-05a00967f06885a63"
    }
  ],
  "vpc_id":"vpc-0b0f2397039aefca8",
  "subnet_id":"subnet-028fb8a226cdc8c98",
  "key_name":"latest"
}
lock = 0

queue=[]

# agent bacground

agent_bacground ='you are a l1 engineer responsible for basic troubleshooting so do basic troubleshooting if the issue is resolved even temporaraly its resolved you are also responsible for completeing basic service requests and if the issue is not resolved escalate it to l2 engineer'

# assistant = pc.assistant.create_assistant(
#     assistant_name="metalaiassistant", 
#     instructions="Answer directly and succinctly. Do not provide any additional information.", # Description or directive for the assistant to apply to all responses.
#     timeout=30 # Wait 30 seconds for assistant operation to complete.
# )

class ssh(BaseModel):

    key_file: str
class CMDBItem(BaseModel):
    tag_id: str
    ip: IPvAnyAddress
    addr: str
    type: str
    description: str
    # No need to include user_id in the request body as we'll get it from the token

class CMDBItemUpdate(BaseModel):
    tag_id: Optional[str] = None
    ip: Optional[IPvAnyAddress] = None
    addr: Optional[str] = None
    os: Optional[str] = None
    type: Optional[str] = None
    description: Optional[str] = None

class Snow_key(BaseModel):
    snow_key: str
    snow_instance: str
    snow_user: str
    snow_password: str

class Aws(BaseModel):
    access_key: str
    secrete_access: str 
    region: str
    instance_id: str

class IncidentMail(BaseModel):
    inc_number: str
    subject: str
    message: str

class RequestBody(BaseModel):
    Aws: Aws
    Mail: IncidentMail  
    
class Incident(BaseModel):
    id: Union[int,None]
    short_description: str
    tag_id: str
    state: Union[str, None]
    inc_number: Union[str, None]

class Mesage(BaseModel):
    content: str

# def powerStatus(Aws: Aws):
#     model = genai.GenerativeModel("gemini-1.5-flash")

#     varfiles :str = f"aws_access_key_id: '{Aws.access_key}'\naws_secret_access_key: '{Aws.secrete_access}'\naws_region: '{Aws.region}'"

#     with open("aws_credentials.yml", "w") as file:
#         file.write(varfiles)
#     playbookurl ="https://s3.ap-south-1.amazonaws.com/infra.ai/awsdiscovery.yml"
#     response= requests.get(playbookurl)

#     with open("awsdiscovery.yml", "w") as file:
#         file.write(response.text)

#     subprocess.run("ansible-playbook awsdiscovery.yml", shell=True)

#     awsassets={}

#     with open("aws_assets.json", "r") as file:
#         awsassets = file.read()

#     os.remove("awsdiscovery.yml")
#     os.remove("aws_credentials.yml")
#     os.remove("aws_assets.json")
    

#     response = model.generate_content(f"from the given {awsassets} find the status of the instance of the instanceid {Aws.instance_id} just return the status not anything else")
#     print(response.parts[0].text)    
#     return {"response": response.parts[0].text}

import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import requests
import subprocess
import os
import boto3
from typing import Dict, Any

def send_escalation_email(subject: str, message: str, recipient: str):
    # """
    # Sends an escalation email.
    # """
    # sender_email = "swiftgmr@gmail.com"
    # sender_password = "swiftGMR@123"
    # smtp_server = "smtp.gmail.com"
    # smtp_port = 587

    try:
        # Create the email
        # msg = MIMEMultipart()
        # msg["From"] = sender_email
        # msg["To"] = recipient
        # msg["Subject"] = subject
        # msg.attach(MIMEText(message, "plain"))

        # # Send the email
        # with smtplib.SMTP(smtp_server, smtp_port) as server:
        #     server.starttls()
        #     server.login(sender_email, sender_password)
        #     server.sendmail(sender_email, recipient, msg.as_string())
        return "Email sent successfully ."+message
    except Exception as e:
        print(f"Failed to send escalation email: {str(e)}")

def power_status_tool(Aws: Aws):
    """
    Executes the power status check and takes action based on the status.
    """
    # Initialize the Gemini model
    model = genai.GenerativeModel("gemini-2.0-flash-exp")

    # Generate AWS credentials file
    varfiles = (
        f"aws_access_key_id: '{Aws['access_key']}'\n"
        f"aws_secret_access_key: '{Aws['secrete_access']}'\n"
        f"aws_region: '{Aws['region']}'"
    )

    try:
        with open("aws_credentials.yml", "w") as file:
            file.write(varfiles)

        # Download and save the discovery playbook
        playbook_url = "https://s3.ap-south-1.amazonaws.com/infra.ai/awsdiscovery.yml"
        response = requests.get(playbook_url)
        with open("awsdiscovery.yml", "w") as file:
            file.write(response.text)

        # Run the Ansible playbook
        subprocess.run("ansible-playbook awsdiscovery.yml", shell=True)

        # Read the output assets
        aws_assets = {}
        try:
            with open("aws_assets.json", "r") as file:
                aws_assets = file.read()
        finally:
            # Cleanup temporary files
            os.remove("awsdiscovery.yml")
            os.remove("aws_credentials.yml")
            os.remove("aws_assets.json")

        # Use the Gemini model to process the instance status
        query = (
            f"From the given {aws_assets}, find the status and OS information of the instance with ID {Aws['instance_id']}. "
            "Just return the status  and  and not anything else."
        )
        response = model.generate_content(query)
        status= response.parts[0].text.strip()
        query1 = (
            f"From the given {aws_assets}. "
            "Just return the public ipv4 information and not anything else dont include exta spaces quotes or escape charecters."
        )
        
        query2 = (
            f"From the given {aws_assets}, find the status and OS information of the instance with ID {Aws['instance_id']}. "
            "Just return the os and flavour of os like amazon linux or rhel form the  etc  and  and not anything else."
        )
        response2 = model.generate_content(query2)
        osinfo= response2.parts[0].text.strip()
        response1 = model.generate_content(query1)
        ipv4 = response1.parts[0].text.strip()
        
        print(status,osinfo,ipv4[0:11]),
        # Initialize boto3 client
        ec2 = boto3.client(
            "ec2",
            aws_access_key_id=Aws["access_key"],
            aws_secret_access_key=Aws["secrete_access"],
            region_name=Aws["region"],
        )

        # Decide action based on the status
        action = ""
        if "stopped" in status.lower():
            action = f"Instance {Aws['']} is stopped. Attempting to start it."
            try:
                print(f"--- execute_plan_generator: Attempting plan_item: Action: {plan_item.action}, Desc: {plan_item.description}")
                ec2.start_instances(InstanceIds=[Aws['instance_id']])
                action += " Instance has been started successfully."
            except Exception as e:
                action += f" Failed to start instance. Error: {str(e)}"
                send_escalation_email(
                    subject="AWS Instance Start Failure",
                    message=f"Failed to start instance {Aws['instance_id']}. Error: {str(e)}",
                    recipient="mgm15072002@gmail.com",
                )
        elif "running" in status.lower():
            action = f"Instance {Aws['instance_id']} Instance has been started successfully."
        else:
            action = f"Instance {Aws['instance_id']} status is unknown. Escalating to L2 engineer."
            send_escalation_email(
                subject="AWS Instance Status Unknown",
                message=f"The status of instance {Aws['instance_id']} could not be determined.",
                recipient="swiftgmr@gmail.com",
            )

        return {"status_and_os_info": status, "action": action, "ipv4": ipv4,"os":osinfo}

    except Exception as e:
        # Escalate in case of any unexpected errors
        send_escalation_email(
            subject="AWS Power Status Tool Error",
            message=f"An error occurred in the PowerStatusTool: {str(e)}",
            recipient="mgm15072002@gmail.com",
        )
        return {"status_and_os_info": "error", "action": f"Escalated due to error: {str(e)}"}


def selfHealing(Aws:Aws,Mail:IncidentMail):
    
    response1 = power_status_tool(Aws)
    model = genai.GenerativeModel("gemini-2.0-flash-exp")
    print(response1)

    if("Instance has been started successfully." in response1['action']):
        #known_erros=askQuestion(f"An incident has been recivied with the subject {Mail.subject} and message {Mail.message} and the instance has been started successfully and {response['status_and_os_info']} is the os from ih there is an information in the document give it")
        aicommands = model.generate_content(f"An incident has been recivied with the subject {Mail['subject']} and message {Mail['message']} and the instance has been started successfully generate commands to fix the issue just return the commands and {response1['os']} is the os give the username of it its based on on aws and the public ipv4 is {response1['ipv4']} ssh is already connected so skip it and fit all the things in as single line such as if high cpu usage combine both monitoring the process and killing it in a single command and dont use interactive commands your background is {agent_bacground}")
        lock = 1
        res=execute_command(aicommands.parts[0].text,response1["ipv4"],'ec2-user',Mail['subject'],Mail['inc_number'])
        if("resolved" in res):
            lock = 0
            res=supabase.table("Incidents").update({"state": "Resolved"}).eq("inc_number", Mail['inc_number']).execute()
            supabase.table("")
            return{"response": "done", "output": res}
        elif("not resolved" in res):
            lock = 0
            res1=supabase.table("Incidents").update({"state": "NotResolved"}).eq("inc_number", Mail['inc_number']).execute()
            return{"response": "not resolved"}
        elif("Email sent to L2 engineer" in res):
            lock = 0
            res2=supabase.table("Incidents").update({"state": "Escalated"}).eq("inc_number", Mail["inc_number"]).execute()
            return{"response": "done email sent to L2 engineer, output: "+res}
        else:
            lock = 0
            res2=supabase.table("Incidents").update({"state": "Resolved"}).eq("inc_number", Mail["inc_number"]).execute()

            return{"response": "done", "output": res}
    else:
        return{"response": "error"}
    
def execute_command(command: str,hostname: str,username: str,incident:str,inc_number:str):
    model = genai.GenerativeModel("gemini-2.0-flash-exp")
    getSSHKeys(r.get('userjwt'))
    #res1 =model.generate_content(f"if the issue is resolved from this context {command}")
   
    # host1=model.generate_content(f"just return the host ipv4{command}")
    # username1 = model.generate_content(f"just return the username{command}")
    # SSH connection details
    host = hostname
    username = username
    key_file = "./key.pem"

# Create SSH client
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(host, username=username, key_filename=key_file)
    print("Connected to SSH")

# Generate the command to be executed
    command1 = model.generate_content(
    f"just return the command {command} so that it can be executed in a single line don't return anything else without any extra space or anything extra other than command don't convert it into script just return the command as string of multiline use multiple line separator ssh is already connected so skip it and fit all the things in as single line remove bash and remove ``` and if using pid wrap it with tripple quotes dont use interactive commands while using commands like top use -b for load based issues first check and then try to resolve it if its alright then dont try to resolve it or try to kill the process if its not resolved"
    ).parts[0].text

# Execute command with TERM environment variable set
    full_command = f"export TERM=xterm-256color && {command1}"
    print(full_command)
    stdin, stdout, stderr = ssh.exec_command(full_command)
    output = stdout.read().decode()
    error = stderr.read().decode()

    print(output)
    print(error)

# Close SSH connection
    ssh.close()
    os.remove("./key.pem")

    result1 = model.generate_content(f"with the given incident context {incident} and output of command run {output} command {full_command} if the incident is resolved just send resolved or send unresolved if the icident like cpu usage than if the cpu usage see load first has gone down at that point it is resolved same for disk and all load based issues your backgeound is {agent_bacground} even if its a temporary solution if the issue is fixed return resolved").parts[0].text
    print(result1)

    

    # Interpret the output using the model

    # Check if the incident is resolved
    if "not resolved" in result1.lower():
        # Send an email to the L2 engineer
        send_mail_to_l2_engineer(command, output, error)
        return {"output": output, "error": error, "result": "Email sent to L2 engineer"}
    else:
        res=supabase.table("Incidents").update({"state": "Resolved"}).eq("inc_number", inc_number).execute()
        supabase.table("Results").insert({"inc_number": inc_number,"description":output}).execute()
        return {"output": output, "error": error,"result": result1} 

# def is_incident_resolved(result):
#     model = genai.GenerativeModel("gemini-1.5-flash")
#     res = model.generate_content(f"if the incident is resolved return resolved else return not resolved {result}")
#     # Implement logic to determine if the incident is resolved
#     if("resolved" in res.parts[0].text):
#         return "resolved" in result.lower()
#     else:
#         return "not resolved" in result.lower()

def send_mail_to_l2_engineer(command, output, error):
    # sender_email = "swiftgmr@gmail.com"
    # receiver_email = "mgm15072002@gmail.com"
    # subject = "Incident Failed to Resolve"
    # body = f"""
    # Command: {command}
    # Output: {output}
    # Error: {error}
    # """

    # # Create email message
    # msg = MIMEMultipart()
    # msg['From'] = sender_email
    # msg['To'] = receiver_email
    # msg['Subject'] = subject
    # msg.attach(MIMEText(body, 'plain'))

    # # Send email
    # with smtplib.SMTP('smtp.example.com', 587) as server:
    #     server.starttls()
    #     server.login(sender_email, "swiftGMR@123")
    #     server.sendmail(sender_email, receiver_email, msg.as_string())
    return "Email sent to L2 engineer"+command+output+error
@app.post("/addKnowledge")
def addKnowledge(file: UploadFile = File(...),):

    with open("Sop.pdf", "wb") as buffer:
        buffer.write(file.file.read())
    # Get the assistant.
    assistant1 = pc.assistant.Assistant(
    assistant_name="metalaiassistant", 
    )

# Upload a file.
    response = assistant1.upload_file(
    file_path="./Sop.pdf",
    timeout=None
    )
    os.remove("Sop.pdf")
    return{"response": response}

@app.get("/getKnowledge")
def askQuestion(question: str):
    msg = Message(role='user' ,content=question)
    assistant1 = pc.assistant.Assistant(
    assistant_name="metalaiassistant", 

    )
    resp = assistant1.chat(messages=[msg])
    return {"response": resp['message']['content']}



@app.post("/queueAdd")

def queueAdd(Req:RequestBody):
    sqsqueue = session.resource('sqs').get_queue_by_name(QueueName='infraaiqueue.fifo')
    message_body = json.dumps({
        "Aws": Req.Aws.dict(),
        "Mail": Req.Mail.dict()
    })
    content_hash = hashlib.sha256(message_body.encode()).hexdigest()
    unique_id = f"{content_hash}-{uuid.uuid4().hex}"
    sqsqueue.send_message(
        MessageBody=message_body,
        MessageGroupId=(Req.Mail.inc_number or "infraai").strip()[:128],  # per-incident with safe fallback
        MessageDeduplicationId=unique_id
    )

@app.post("/queueRemove")
def queueRemove():
    sqsqueue=session.resource('sqs').get_queue_by_name(QueueName='infraaiqueue.fifo')
    sqsmess=sqsqueue.receive_messages(MessageAttributeNames=['All'],MaxNumberOfMessages=1)
    print(json.loads(sqsmess[0].body))
    queueici=json.loads(sqsmess[0].body)
    res=supabase.table("Incidents").update({"state": "InProgress"}).eq("inc_number", queueici["Mail"]['inc_number']).execute()
    #return{"Aws": queueici['Aws'], "Mail": queueici['Mail']}
   
    if lock == 0:
        res=selfHealing(queueici["Aws"],queueici["Mail"])
        
        return{"response": res}
    else:
        return{"response": "worker in progress"}

    
os.environ['TERM'] = 'xterm-256color'

@app.post("/testecodeexec/{hostname}/{username}")
def testecodeexec(hostname: str,username: str):
    res=execute_command("top -bn1 | grep -v ""PID"" | sort -k9 -r | head -n 1 | awk '{print $1}' | xargs kill -9",hostname,username,"cpu usage is high")
    return{"response": res}
@app.post("/testAws")
def testAws(Aws: Aws):
    res=power_status_tool(Aws)
    return{"response": res}
    
@app.post("/uploadSSH")
def uploadSSH(credentials: Annotated[HTTPAuthorizationCredentials, Depends(security)], ssh:ssh):
    
    # subprocess.run(['chmod', '600', 'key.pem'])
    secret_auth_uri = "https://app.infisical.com/api/v1/auth/universal-auth/login"
    
    # Proper headers format as a dictionary
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    
    # Proper data format for the authentication request
    auth_data = {
        "clientSecret": os.getenv('clientSecret'),
        "clientId": os.getenv('clientId')
    }
    try:
        token = credentials.credentials
        res=jwt.decode(token, key=clerk_public_key, algorithms=['RS256'])
        mail=res['email']
    except jwt.DecodeError as e:
        print(e)
        return({"error":e})

    try:
        # Get access token
        response = requests.post(url=secret_auth_uri, headers=headers, data=auth_data)
        response.raise_for_status()  # Raise exception for bad status codes
        access_token = response.json()['accessToken']
       
        #Headers for subsequent requests
        auth_headers = {
            'Authorization': f'Bearer {access_token}'
        }
    except:
        print("error")
    url = f"https://us.infisical.com/api/v3/secrets/raw/SSH_KEY_{mail}"
    

    payload = {
    "environment": "prod",
    "secretValue": ssh.key_file,
    "workspaceId": "113f5a41-dbc3-447d-8b3a-6fe8e9e6e99c"
    }

    #json_payload = json.dumps(payload)

    
    headers = {
    "Authorization": auth_headers['Authorization'],
    "Content-Type": "application/json"
}

    response = requests.request("POST", url, json=payload, headers=headers)
    os.remove("key.pem")
    return{"response": "done"}




def getAwsKeys(mail:str):
     secret_auth_uri = "https://app.infisical.com/api/v1/auth/universal-auth/login"
    
    # Proper headers format as a dictionary
     headers = {
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    
    # Proper data format for the authentication request
     auth_data = {
        "clientSecret": os.getenv('clientSecret'),
        "clientId": os.getenv('clientId')
    }
    
     try:
        # Get access token
        response = requests.post(url=secret_auth_uri, headers=headers, data=auth_data)
        response.raise_for_status()  # Raise exception for bad status codes
        access_token = response.json()['accessToken']
       
        #Headers for subsequent requests
        auth_headers = {
            'Authorization': f'Bearer {access_token}'
        }
        
        # Get AWS credentials
        base_url = 'https://us.infisical.com/api/v3/secrets/raw'
        aws_credentials = {
            'aws_access_key_id': requests.get(f'{base_url}/AWS_ACCESS_KEY_{mail}?workspaceSlug=infraai-oqb-h&environment=prod', headers=auth_headers).json(),
            'aws_secret_access_key': requests.get(f'{base_url}/AWS_SECRET_KEY_{mail}?workspaceSlug=infraai-oqb-h&environment=prod', headers=auth_headers).json(),
            'aws_region': requests.get(f'{base_url}/AWS_REGION_{mail}?workspaceSlug=infraai-oqb-h&environment=prod', headers=auth_headers).json()
            
        }
        #print(aws_credentials)
     except :
        print("error")
     awskeys:Aws={"access_key": aws_credentials['aws_access_key_id']['secret']['secretValue'], "secrete_access": aws_credentials['aws_secret_access_key']['secret']['secretValue'], "region": aws_credentials['aws_region']['secret']['secretValue']}
     return{'response':awskeys}
def getSnowKeys(mail: str):
    secret_auth_uri = "https://app.infisical.com/api/v1/auth/universal-auth/login"
    
    # Proper headers format as a dictionary
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    
    # Proper data format for the authentication request
    auth_data = {
        "clientSecret": os.getenv('clientSecret'),
        "clientId": os.getenv('clientId')
    }
    
    try:
        # Get access token
        response = requests.post(url=secret_auth_uri, headers=headers, data=auth_data)
        response.raise_for_status()  # Raise exception for bad status codes
        access_token = response.json()['accessToken']
        
        # Headers for subsequent requests
        auth_headers = {
            'Authorization': f'Bearer {access_token}'
        }
        
        # Get ServiceNow credentials
        base_url = 'https://us.infisical.com/api/v3/secrets/raw'
        snow_credentials = {
            'snow_key': requests.get(f'{base_url}/SNOW_KEY_{mail}?workspaceSlug=infraai-oqb-h&environment=prod', headers=auth_headers).json(),
            'snow_instance': requests.get(f'{base_url}/SNOW_INSTANCE_{mail}?workspaceSlug=infraai-oqb-h&environment=prod', headers=auth_headers).json(),
            'snow_user': requests.get(f'{base_url}/SNOW_USER_{mail}?workspaceSlug=infraai-oqb-h&environment=prod', headers=auth_headers).json(),
            'snow_password': requests.get(f'{base_url}/SNOW_PASSWORD_{mail}?workspaceSlug=infraai-oqb-h&environment=prod', headers=auth_headers).json()
        }
    except:
        print("error")
    
    snowkeys: Snow_key = {
        "snow_key": snow_credentials['snow_key']['secret']['secretValue'], 
        "snow_instance": snow_credentials['snow_instance']['secret']['secretValue'], 
        "snow_user": snow_credentials['snow_user']['secret']['secretValue'],
        "snow_password": snow_credentials['snow_password']['secret']['secretValue']
    }
    
    return {'response': snowkeys}
@app.get("/getSnowKey/{mail}")
def getSnowKeys(mail: str):
    secret_auth_uri = "https://app.infisical.com/api/v1/auth/universal-auth/login"
    
    # Proper headers format as a dictionary
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    
    # Proper data format for the authentication request
    auth_data = {
        "clientSecret": os.getenv('clientSecret'),
        "clientId": os.getenv('clientId')
    }
    
    try:
        # Get access token
        response = requests.post(url=secret_auth_uri, headers=headers, data=auth_data)
        response.raise_for_status()  # Raise exception for bad status codes
        access_token = response.json()['accessToken']
        
        # Headers for subsequent requests
        auth_headers = {
            'Authorization': f'Bearer {access_token}'
        }
        
        # Get ServiceNow credentials
        base_url = 'https://us.infisical.com/api/v3/secrets/raw'
        snow_credentials = {
            'snow_key': requests.get(f'{base_url}/SNOW_KEY_{mail}?workspaceSlug=infraai-oqb-h&environment=prod', headers=auth_headers).json(),
            'snow_instance': requests.get(f'{base_url}/SNOW_INSTANCE_{mail}?workspaceSlug=infraai-oqb-h&environment=prod', headers=auth_headers).json(),
            'snow_user': requests.get(f'{base_url}/SNOW_USER_{mail}?workspaceSlug=infraai-oqb-h&environment=prod', headers=auth_headers).json(),
            'snow_password': requests.get(f'{base_url}/SNOW_PASSWORD_{mail}?workspaceSlug=infraai-oqb-h&environment=prod', headers=auth_headers).json()
        }
    except:
        print("error")
    
    snowkeys: Snow_key = {
        "snow_key": snow_credentials['snow_key']['secret']['secretValue'], 
        "snow_instance": snow_credentials['snow_instance']['secret']['secretValue'], 
        "snow_user": snow_credentials['snow_user']['secret']['secretValue'],
        "snow_password": snow_credentials['snow_password']['secret']['secretValue']
    }
    
    return {'response': snowkeys}
@app.get("/getSSHKeys/{mail}")
def getSSHKeys(mail:str):
     secret_auth_uri = "https://app.infisical.com/api/v1/auth/universal-auth/login"
    
    # Proper headers format as a dictionary
     headers = {
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    
    # Proper data format for the authentication request
     auth_data = {
        "clientSecret": os.getenv('clientSecret'),
        "clientId": os.getenv('clientId')
    }
    
     try:
        # Get access token
        response = requests.post(url=secret_auth_uri, headers=headers, data=auth_data)
        response.raise_for_status()  # Raise exception for bad status codes
        access_token = response.json()['accessToken']
       
        #Headers for subsequent requests
        auth_headers = {
            'Authorization': f'Bearer {access_token}'
        }
        
        # Get AWS credentials
        base_url = 'https://us.infisical.com/api/v3/secrets/raw'
        sshkey =  requests.get(f'{base_url}/SSH_KEY_{mail}?workspaceSlug=infraai-oqb-h&environment=prod', headers=auth_headers).json(),
        
        with open("key.pem", "wb") as file:
            
            file.write(sshkey[0]['secret']['secretValue'].encode('utf-8'))
        return {"key_file": sshkey[0]['secret']['secretValue']}
     except :
        print("error")
    
@app.get("/getAwsKeys/{mail}")
def getAwsKeys(mail:str):
     secret_auth_uri = "https://app.infisical.com/api/v1/auth/universal-auth/login"
    
    # Proper headers format as a dictionary
     headers = {
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    
    # Proper data format for the authentication request
     auth_data = {
        "clientSecret": os.getenv('clientSecret'),
        "clientId": os.getenv('clientId')
    }
    
     try:
        # Get access token
        response = requests.post(url=secret_auth_uri, headers=headers, data=auth_data)
        response.raise_for_status()  # Raise exception for bad status codes
        access_token = response.json()['accessToken']
       
        #Headers for subsequent requests
        auth_headers = {
            'Authorization': f'Bearer {access_token}'
        }
        
        # Get AWS credentials
        base_url = 'https://us.infisical.com/api/v3/secrets/raw'
        aws_credentials = {
            'aws_access_key_id': requests.get(f'{base_url}/AWS_ACCESS_KEY_{mail}?workspaceSlug=infraai-oqb-h&environment=prod', headers=auth_headers).json(),
            'aws_secret_access_key': requests.get(f'{base_url}/AWS_SECRET_KEY_{mail}?workspaceSlug=infraai-oqb-h&environment=prod', headers=auth_headers).json(),
            'aws_region': requests.get(f'{base_url}/AWS_REGION_{mail}?workspaceSlug=infraai-oqb-h&environment=prod', headers=auth_headers).json()
            
        }
        #print(aws_credentials)
     except :
        print("error")
     awskeys:Aws={"access_key": aws_credentials['aws_access_key_id']['secret']['secretValue'], "secrete_access": aws_credentials['aws_secret_access_key']['secret']['secretValue'], "region": aws_credentials['aws_region']['secret']['secretValue']}
     return{'response':awskeys}


@app.get("/getIncidentsDetails/{inc_number}")
def getIncidentsDetails(inc_number: str):
   response = supabase.from_("Incidents").select("short_description").eq("inc_number", inc_number).execute()
   short_desc = response.data[0]["short_description"] if response.data else "No description provided."

# 🤖 Init Mistral model via LangChain
   llm = init_chat_model("mistral-large-latest", model_provider="mistralai")

# 🧠 Prompt template
   prompt = ChatPromptTemplate.from_messages([
    ("system", "You are an expert incident responder."),
    ("user", 
    """Given the following incident short description, determine:
1. potential_cause
2. potential_solution

Respond only in JSON format like this:
{{"potential_cause": "...", "potential_solution": "..."}}

Short description: {short_description}
{format_instructions}
""")
])

# 🧾 JSON Parser
   parser = JsonOutputParser()

# 🔗 Chain
   chain: Runnable = prompt | llm | parser

# 🚀 Execute
   result = chain.invoke({
    "short_description": short_desc,
    "format_instructions": parser.get_format_instructions()
})
   result['description']= short_desc
# 🖨️ Output
   print(result)



   return{"response": result}  


@app.post("/addSNOWCredentials")
def addSnowCredentials(snow: Snow_key, credentials: Annotated[HTTPAuthorizationCredentials, Depends(security)], response: Response):
    secret_auth_uri = "https://app.infisical.com/api/v1/auth/universal-auth/login"
    
    # Proper headers format as a dictionary
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    
    # Proper data format for the authentication request
    auth_data = {
        "clientSecret": os.getenv('clientSecret'),
        "clientId": os.getenv('clientId')
    }
    
    try:
        token = credentials.credentials
        res = jwt.decode(token, key=clerk_public_key, algorithms=['RS256'])
        mail = res['email']
        
        try:
            # Get access token
            response = requests.post(url=secret_auth_uri, headers=headers, data=auth_data)
            response.raise_for_status()  # Raise exception for bad status codes
            access_token = response.json()['accessToken']
            
            # Headers for subsequent requests
            auth_headers = {
                'Authorization': f'Bearer {access_token}'
            }
        except:
            print("error")
    except jwt.DecodeError as e:
        response.status_code = status.HTTP_400_BAD_REQUEST
        return {"message": e}
    
    # Create dictionary for ServiceNow credentials
    snowdict = {
        f"SNOW_KEY_{mail}": snow.snow_key,
        f"SNOW_INSTANCE_{mail}": snow.snow_instance,
        f"SNOW_USER_{mail}": snow.snow_user,
        f"SNOW_PASSWORD_{mail}": snow.snow_password
    }
    
    # Add each credential to Infisical
    for key, value in snowdict.items():
        url = f"https://us.infisical.com/api/v3/secrets/raw/{key}"
        payload = {
            "environment": "prod",
            "secretValue": value,
            "workspaceId": "113f5a41-dbc3-447d-8b3a-6fe8e9e6e99c"
        }
        
        headers = {
            "Authorization": auth_headers['Authorization'],
            "Content-Type": "application/json"
        }
        
        response = requests.request("POST", url, json=payload, headers=headers)
    
    return {"response": "done"}

@app.post("/addAwsCredentials")

def addAwsCredentials(Aws: Aws,credentials: Annotated[HTTPAuthorizationCredentials, Depends(security)],
    response: Response):
    secret_auth_uri = "https://app.infisical.com/api/v1/auth/universal-auth/login"
    
    # Proper headers format as a dictionary
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    
    # Proper data format for the authentication request
    auth_data = {
        "clientSecret": os.getenv('clientSecret'),
        "clientId": os.getenv('clientId')
    }
    try:
         token = credentials.credentials
         res=jwt.decode(token, key=clerk_public_key, algorithms=['RS256'])
         mail=res['email']
         try:
        # Get access token
            response = requests.post(url=secret_auth_uri, headers=headers, data=auth_data)
            response.raise_for_status()  # Raise exception for bad status codes
            access_token = response.json()['accessToken']
       
       
        #Headers for subsequent requests
            auth_headers = {
            'Authorization': f'Bearer {access_token}'
            }
         except:
            print("error")
    except jwt.DecodeError as e :
        response.status_code = status.HTTP_400_BAD_REQUEST
        return {"message": e}

   
    
   
        
    awsdict={
        f"AWS_ACCESS_KEY_{mail}": Aws.access_key,
        f"AWS_SECRET_KEY_{mail}": Aws.secrete_access,
        f"AWS_REGION_{mail}": Aws.region
    }
    for key, value in awsdict.items():
            url = f"https://us.infisical.com/api/v3/secrets/raw/{key}"
            payload = {
    "environment": "prod",
    "secretValue": value,
    "workspaceId": "113f5a41-dbc3-447d-8b3a-6fe8e9e6e99c"
    }   
            headers = {
    "Authorization": auth_headers['Authorization'],
    "Content-Type": "application/json"
}
            response = requests.request("POST", url, json=payload, headers=headers)

    return {"response": "done"}
   
        

    
    
    #json_payload = json.dumps(payload)
async def verify_token(credentials: Annotated[HTTPAuthorizationCredentials, Depends(security)]):
    try:
        token = credentials.credentials
        payload = jwt.decode(token, key=clerk_public_key, algorithms=['RS256'])
        email = payload.get("email")
        if email is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials - email not found",
            )
        user_response = supabase.table("Users").select("id").eq("email", email).execute()
        if not user_response.data or len(user_response.data) == 0:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        user_id = user_response.data[0]["id"]
        return {"email": email, "user_id": user_id}
    except PyJWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials - invalid token",
        )
    
@app.get("/allIncidents")

def allIncidents(user_data: dict = Depends(verify_token)):

    mail = user_data['email']

    user_response = supabase.table("Users").select("id").eq("email", mail).execute()
    
    if user_response.data and len(user_response.data) > 0:
        user_id = user_response.data[0]['id']
        # Then query incidents by user_id
        response = supabase.table("Incidents").select("*, Users(*)").eq("user_id", user_id).execute()
    return{"response": response}

@app.post("/storeJwt/{jwt}")

def addJWT(jwt:str):
    
    r.set('userjwt',jwt)


def get_sys_id(mapping: dict, key: str) -> str:
    """Retrieve the sys_id from a given mapping dictionary."""
    return mapping.get(key, "")

# Example sys_id mappings (Replace with actual values)
sys_id_mapping = {
    "caller": {
        "AutoDispatcher": "3061476f838712101c9aba96feaad322",
        "Jane Smith": "sys_id_456",
    },
    "assignment_group": {
        "L1 queue": "588536e7838712101c9aba96feaad3fe",
        "Security Team": "sys_id_101",
    },
    "assigned_to": {
        "AutoDispatcher": "3061476f838712101c9aba96feaad322",
        "Engineer": "sys_id_303",
    },
    "state":{
        "new": 1,
        "in_progress": 2,
        "on_hold": 3,
        "resolved": 6,
        "closed": 7,
        "canceled": 8
    },
    "impact":{
        "low": 3,
        "medium": 2,
        "high": 1
    },
    "urgency":{
        "low": 3,
        "medium": 2,
        "high": 1
    },
   "close_code": {

    
    
    "No resolution provided": "No resolution provided",
    "Resolved by request": "Resolved by request",
    "Resolved by caller": "Resolved by caller",
    "Solution provided": "Solution provided",
    "Duplicate": "Duplicate",
    "Resolved by change": "Resolved by change",
    "Workaround provided": "Workaround provided",
    "Known error": "Known error",
    "Resolved by problem": "Resolved by problem",
    "User error": "User error"


},
    "close_notes":{"provide notes while closing or updating the incident"},
    "work_notes":{"provide notes while closing or updating the incident"}
}



@tool
def create_incident(create:Dict,mail:str):
    """
    Create an incident in ServiceNow.
    """
    
    model = genai.GenerativeModel("gemini-2.0-flash-thinking-exp-01-21")
    res=model.generate_content(f"this is the update I want to do to the incident {create}, this is the sysid and other mappings {sys_id_mapping} generate a body to send to rest api dont do anything else just give the json dont add backticks or json in the result come up with an urgence and impact value based on priority keep the as numbers only fill short_description and description as well")
    body=res.parts[0].text
    match = re.search(r'\{.*\}', body, re.DOTALL)
    if match:
        json_data = match.group()
        parsed_json = json.loads(json_data)  # Convert to dictionary if needed
        print(parsed_json)  # 
    
    # payload = {
    #     "caller_id": get_sys_id(sys_id_mapping["caller"], caller),
    #     "assignment_group": get_sys_id(sys_id_mapping["assignment_group"], assignment_group),
    #     "short_description": short_description,
    #     "assigned_to": get_sys_id(sys_id_mapping["assigned_to"], assigned_to),
    # }

    SERVICENOW_URL = getSnowKeys(mail=mail)['response']['snow_instance'] + "/api/now/table/incident"
    HEADERS = {
    "Content-Type": "application/json",
    "x-sn-apikey": getSnowKeys(mail=mail)['response']['snow_key'],
    }
    parsed_json['urgency']=int(parsed_json['urgency'])
    parsed_json['impact']=int(parsed_json['impact'])
    response = requests.post(SERVICENOW_URL, json=parsed_json, headers=HEADERS)
    return response.json() if response.status_code == 201 else {"status": "failed", "message": response.text}

@tool
def update_incident(incident_number: str, updates: dict,mail:str):

    """Update an incident using its incident number."""
    Snow_res=getSnowKeys(mail=mail)
    SERVICENOW_URL = Snow_res['response']['snow_instance']+ "/api/now/table/incident"
    HEADERS = {
    "Content-Type": "application/json",
    "x-sn-apikey": getSnowKeys(mail=mail)['response']['snow_key'],
    }

    username= Snow_res['response']['snow_user']
    password= Snow_res['response']['snow_password']
    model = genai.GenerativeModel("gemini-2.0-flash-thinking-exp-01-21")
    res=model.generate_content(f"this is the update I want to do to the incident {updates}, this is the sysid and other mappings {sys_id_mapping} generate a body to send to rest api dont do anything else just give the json dont add backticks or json in the result come up with an urgence and impact value based on priority keep them as number only and when i am closing the incident include close_code and clouser_notes should have the following format clouser_notes:the clouser notes provided add work_notes to this while updating an incident")
    #resnew=model.generate_content(f"add work_notes to this {res} if the inicdent is being closed generate a body to send to rest api dont do anything else")
    body=res.parts[0].text
    match = re.search(r'\{.*\}', body, re.DOTALL)
    if match:
        json_data = match.group()
        parsed_json = json.loads(json_data)  # Convert to dictionary if needed
        print(parsed_json)  # 

        Updateurl=SERVICENOW_URL+f"?sysparm_limit=10&number={incident_number}"
    
    response = requests.get(Updateurl, headers=HEADERS ,auth=HTTPBasicAuth(username,password))
    # if response.status_code != 200 or "result" not in response.json():
    #     return {"status": "failed", "message": "Incident not found"}
    #print(response.json())
    incident_sys_id = response.json()['result'][0]["sys_id"]
    update_url = f"{SERVICENOW_URL}/{incident_sys_id}"
    
    response = requests.patch(update_url, json=parsed_json, headers=HEADERS)
    return response.json() if response.status_code == 200 else {"status": "failed", "message": response.text}

@tool
def get_incident_details(incident_number: str,mail:str):
    """
    Retrieve incident details from ServiceNow using the incident number.
    """
    Snow_res=getSnowKeys(mail=mail)
    SERVICENOW_URL = Snow_res['response']['snow_instance']+ "/api/now/table/incident"
    HEADERS = {
    "Content-Type": "application/json",
    "x-sn-apikey": getSnowKeys(mail=mail)['response']['snow_key'],
    }

    username= Snow_res['response']['snow_user']
    password= Snow_res['response']['snow_password']
    
    # Construct the URL with query parameter to find the incident by number
    query_url = f"{SERVICENOW_URL}?sysparm_limit=10&number={incident_number}"
    
    # Send GET request to ServiceNow API with basic authentication
    response = requests.get(
        query_url, 
        headers=HEADERS,
        auth=HTTPBasicAuth(username, password)
    )
    
    # Check if request was successful and results were found
    if response.status_code == 200 and "result" in response.json() and response.json()['result']:
        # Return the full incident details
        return response.json()['result'][0]
    else:
        # Return error information if incident not found or request failed
        return {
            "status": "failed", 
            "message": f"Incident not found or error occurred: {response.text}"
        }
@tool
def infra_automation_ai(mesaage:str,mail:str):
    '''this function is used to automate the infrastructure related tasks'''
#     client = OpenAI(
#     base_url="https://api.sree.shop/v1",
#     api_key="",
#     )

#     completion = client.chat.completions.create(
 
   
#     model="gpt-4o",
#     messages=[
#     {
#       "role": "system",
#       "content": f"Automate the infrastructure related tasks using the given context {system_prompt} dont do circular dependency the request {mesaage} and the data . For variables use {amazon_context} and add varibles inside the playboof only for aws access key secrete key and region vars.yml is createdreturn the response dont add any extra information"
#     },{
#         "role": "user",
#         "content": f"{mesaage}"
#     }   
#   ]
#     )
#     infra_ai=completion.choices[0].message.content
    # model = genai.GenerativeModel("gemini-2.0-flash-thinking-exp-01-21")
    # response = model.generate_content(f"Automate the infrastructure related tasks using the given context {system_prompt} and the request {mesaage} and the data for variables {amazon_context}return the response dont add any extra information")
    # infra_ai= response.parts[0].text
    sections = {}
    messages = [
    (
        "system",
        f"Automate the infrastructure related tasks using the given context {system_prompt} dont do circular dependency the request {mesaage} and the data . For variables use {amazon_context} and add varibles inside the playboof only for aws access key secrete key and region vars.yml is createdreturn the response dont add any extra information",
    ),
    ("human", f"{mesaage}"),
]
    ai_msg = model.invoke(messages)
    infra_ai= ai_msg.content
    # Extract shell commands
    shell_commands_match = re.search(r'<shell_commands>(.*?)</shell_commands>', infra_ai, re.DOTALL)
    if shell_commands_match:
        sections['shell_commands'] = shell_commands_match.group(1).strip()
    
    # Extract inventory file
    inventory_match = re.search(r'<inventory_file>(.*?)</inventory_file>', infra_ai, re.DOTALL)
    if inventory_match:
        sections['inventory_file'] = inventory_match.group(1).strip()
    
    # Extract playbook
    playbook_match = re.search(r'<playbook>(.*?)</playbook>', infra_ai, re.DOTALL)
    if playbook_match:
        sections['playbook'] = playbook_match.group(1).strip()
    playbook_command_match= re.search(r'<playbook_run_command>(.*?)</playbook_run_command>', infra_ai, re.DOTALL)
    if playbook_command_match:
        sections['playbook_command'] = playbook_command_match.group(1).strip()
    files_created = []
    getSSHKeys(mail=mail)
    subprocess.run("chmod 600 key.pem", shell=True)
    
    if 'shell_commands' in sections:
        with open('install_ansible_modules.sh', 'w') as f:
            f.write(sections['shell_commands'])
        os.chmod('install_ansible_modules.sh', 0o755)  # Make the shell script executable
        files_created.append('install_ansible_modules.sh')
    
    if 'inventory_file' in sections:
        with open('inventory_file.ini', 'w') as f:
            f.write(sections['inventory_file'])
        files_created.append('inventory_file.ini')
    
    if 'playbook' in sections:
        with open('playbook.yml', 'w') as f:
            f.write(sections['playbook'])
        files_created.append('playbook.yml')
    if 'playbook_command' in sections:
        with open('playbook_command.sh', 'w') as f:
            f.write(sections['playbook_command'])
            os.chmod('playbook_command.sh', 0o755)
        files_created.append('playbook_command.sh')

    aws_keys = getAwsKeys(mail)
    varfiles = (
        f"aws_access_key: '{aws_keys['response']['access_key']}'\n"
        f"aws_secret_key: '{aws_keys['response']['secrete_access']}'\n"
        f"aws_region: '{aws_keys['response']['region']}'"
    )

    try:
        with open("vars.yml", "w") as file:
            file.write(varfiles)
    except:
        print("error creating varfiles")


    

    shell_output = subprocess.run("./install_ansible_modules.sh", shell=True, capture_output=True, text=True)
    playbook_output=subprocess.run("./playbook_command.sh", shell=True,capture_output=True, text=True)
    os.remove("install_ansible_modules.sh")
    os.remove("inventory_file.ini")
    os.remove("playbook.yml")
    os.remove("vars.yml")
    os.remove("key.pem")
    os.remove("playbook_command.sh")
    
    return {"playbook_output": playbook_output.stdout,"playbook_eror": playbook_output.stderr,"shell_output": shell_output.stdout, "shell_error": shell_output.stderr} 

@tool
def ask_knowledge_base(message:str):
    '''this function is used to ask the knowledge base for the given message to provide context '''
    response = askQuestion(message)
    return {'response': response['response']}

@app.post("/websearch")
async def web_search(message: str, user_data: dict = Depends(verify_token)):
    '''this function is used to search the web for the given message'''
    try:
        # Limit to top 3 most relevant results to reduce processing time
        client = TavilyClient(os.getenv("tavali_api_key"))
        search_response = client.search(
            query=message,
            max_results=3  # Limit results to top 3
        )
        
        # Process results
        async def extract_content(result):
            try:
                # Use requests directly instead of read_url_content
                import requests
                response = requests.get(result['url'], timeout=10)
                
                # Check if request was successful
                if response.status_code == 200:
                    # Use BeautifulSoup for better content extraction
                    from bs4 import BeautifulSoup
                    soup = BeautifulSoup(response.text, 'html.parser')
                    
                    # Extract text content
                    text_content = soup.get_text(separator=' ', strip=True)
                    
                    return {
                        'url': result['url'],
                        'content': text_content[:500]  # Limit content to first 500 characters
                    }
                else:
                    return {
                        'url': result['url'],
                        'content': f'Error: HTTP {response.status_code}'
                    }
            except Exception as e:
                return {
                    'url': result['url'],
                    'content': f'Error extracting content: {str(e)}'
                }
        
        # Gather results
        contexts = await asyncio.gather(*[extract_content(result) for result in search_response['results']])
        
        # Prepare context for Gemini
        context_str = " ".join([ctx['content'] for ctx in contexts if ctx['content']])
        
        # Generate response using Gemini
        gemini = genai.GenerativeModel("gemini-2.0-flash-thinking-exp-01-21")
        response = gemini.generate_content(
            f" you are an helpful web search assistant. Context from web search: {context_str}\n\nQuestion: {message}\n\nGenerate a comprehensive response based on the context, addressing the question directly dont add things like from  the snippet or other unnecessary details."
        )

        return {"response": response.parts[0].text}
        
    except Exception as e:
        return {
            "response": f"Unable to retrieve web search results. Error: {str(e)}. Please try a different query or check your internet connection."
        }

tools = [create_incident, update_incident, get_incident_details,infra_automation_ai]
llm_with_tools = model.bind_tools(tools)

tool_mapping = {"create_incident": create_incident, "update_incident": update_incident,"get_incident_details": get_incident_details,"infra_automation_ai": infra_automation_ai}

@app.post("/chat")
def chat(message:Mesage,credentials: Annotated[HTTPAuthorizationCredentials, Depends(security)],response: Response):
    try:
        token = credentials.credentials
        res=jwt.decode(token, key=clerk_public_key, algorithms=['RS256'])
        mail=res['email']
    except jwt.DecodeError as e:
        print(e)
        return({"error":e})

    gemini = genai.GenerativeModel("gemini-2.0-flash-thinking-exp-01-21")
    enhanced_message = message.content+mail
    messages=[HumanMessage(enhanced_message)]
    res=llm_with_tools.invoke(messages)
    messages.append(res)
    for tool_call in res.tool_calls:
        tool = tool_mapping[tool_call["name"].lower()]
        tool_output = tool.invoke(tool_call["args"])
        messages.append(ToolMessage(tool_output, tool_call_id=tool_call["id"]))
    
    ex2=llm_with_tools.invoke(messages)
    result=gemini.generate_content(f'''generate a response for the given context {ex2} make it short and give only important details related to {message} in sentences dont add unnecessary , or symbols or extra spaces use the {ex2} to provide details and if it failed give details why it failed 
                                   - dont mention the word playbook and word shell commands and word python error  and dont mention this sentence
                                   - A warning was generated regarding the Python interpreter path potentially changing in the future. Galaxy collections installation indicated that all requested collections are already installed. No shell errors were reported and 
                                   - dont mention automation or any such word
                                   - dont mention The platform is using Python interpreter at /usr/bin/python3.12 and future installations might change this path. 5 tasks were completed and 2 were changed. No tasks failed or were unreachable or any similar sentences
                                   - dont mention sentences like tasks executed or 5 tasks run etc
                                   - if anything other than ansible you can mention the entire output of {ex2}''')

    # Extract incident number from the message if it exists
    incident_match = re.search(r'incident\s+(\w+)', message.content, re.IGNORECASE)
    if incident_match:
        inc_number = incident_match.group(1)
        try:
            # Check if incident exists in Supabase
            incident_response = supabase.table("Incidents").select("id").eq("inc_number", inc_number).execute()
            
            if incident_response.data:
                # Update incident status to completed
                supabase.table("Incidents").update({"state": "completed"}).eq("inc_number", inc_number).execute()
        except Exception as e:
            print(f"Error updating incident status: {str(e)}")
            # Continue with the response even if update fails
        
    return({"result":res.tool_calls,"successorfail":result.parts[0].text})

@app.post("/plan")
def getPlan(message: Mesage,user_data: dict = Depends(verify_token)):
    model = init_chat_model("mistral-large-latest", model_provider="mistralai")

   

# 🧾 JSON parser
    parser = JsonOutputParser()

# 🧱 Prompt template
    prompt = ChatPromptTemplate.from_messages([
    ("system", """
You are an assistant that extracts infrastructure change plans from user input. Given a user message, return a JSON object with the key "plan" and the value as a list of bullet points. Each bullet point should describe a specific action to be taken, including:
- The action (created, updated, deleted)
- The type of resource
- The name of the resource
- software asked to be installed or
- any other relevant details.
- always include the name of the resource and the ip adress if any in the all points

When generating plans involving EC2 instances, remember common default usernames:
- Amazon Linux (2 or AMI): ec2-user
- CentOS: centos or ec2-user
- Debian: admin
- Fedora: fedora or ec2-user
- RHEL: ec2-user or root
- SUSE: ec2-user or root
- Ubuntu: ubuntu

Example format:
{{
  "plan": [
    "Create the EC2 instance named web-server",
    "Delete the S3 bucket named old-logs",
    "Update the IAM role named read-only-access",
    "Install software named apache"
  ]
}}

Output only the JSON object. Do not add any extra text, markdown, or newlines before or after. Your response must start with '{{' and end with '}}' with no characters outside. Do not include markdown.
"""),
    ("user", "{user_input}\n{format_instructions}")
])

# 🔗 Chain
    chain: Runnable = prompt | model | parser

# 🚀 Function to run inference

    try:
        result = chain.invoke({
            "user_input": f"The user's request is: {message.content}",
            "format_instructions": parser.get_format_instructions()
        })
        return {"response": result}
        
    except Exception as e:
        return {
            "error": "Failed to parse JSON",
            "message": str(e)
        }
@app.get("/cmdb", response_model=dict)
async def get_all_cmdb_items(user_data: dict = Depends(verify_token)):
    try:
        response = supabase.table("CMDB").select("*, Users(*)").eq("user_id", user_data["user_id"]).execute()
        return {"response": response}
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Database error: {str(e)}"
        )

# Get CMDB item by tag_id (only if it belongs to the authenticated user)
@app.get("/cmdb/{tag_id}", response_model=dict)
async def get_cmdb_item(tag_id: str, user_data: dict = Depends(verify_token)):
    try:
        response = supabase.table("CMDB").select("*, Users(*)").eq("tag_id", tag_id).eq("user_id", user_data["user_id"]).execute()
        if not response.data:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"CMDB item with tag_id {tag_id} not found or does not belong to you"
            )
        return {"response": response}
    except Exception as e:
        if isinstance(e, HTTPException):
            raise e
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Database error: {str(e)}"
        )

# Create new CMDB item with user_id
@app.post("/cmdb", response_model=dict, status_code=status.HTTP_201_CREATED)
async def create_cmdb_item(item: CMDBItem, user_data: dict = Depends(verify_token)):
    try:
        # Check if tag_id already exists for this user
        existing = supabase.table("CMDB").select("tag_id").eq("tag_id", item.tag_id).eq("user_id", user_data["user_id"]).execute()
        if existing.data:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"CMDB item with tag_id {item.tag_id} already exists for this user"
            )
        
        # Create new item with user_id
        response = supabase.table("CMDB").insert({
            "tag_id": item.tag_id,
            "ip": str(item.ip),
            "addr": item.addr,
            "type": item.type,
            "os": item.os,
            "description": item.description,
            "user_id": user_data["user_id"],  # Add user_id from token
            "created_at": datetime.utcnow().isoformat()
        }).execute()
        
        return {"response": response}
    except Exception as e:
        if isinstance(e, HTTPException):
            raise e
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Database error: {str(e)}"
        )

# Update CMDB item (only if it belongs to the authenticated user)
@app.put("/cmdb/{tag_id}", response_model=dict)
async def update_cmdb_item(
    tag_id: str, 
    item: CMDBItemUpdate, 
    user_data: dict = Depends(verify_token)
):
    try:
        # Check if item exists and belongs to this user
        existing = supabase.table("CMDB").select("*").eq("tag_id", tag_id).eq("user_id", user_data["user_id"]).execute()
        if not existing.data:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"CMDB item with tag_id {tag_id} not found or does not belong to you"
            )
        
        # Build update dictionary with only provided fields
        update_data = {}
        if item.tag_id is not None:
            update_data["tag_id"] = item.tag_id
        if item.ip is not None:
            update_data["ip"] = str(item.ip)
        if item.addr is not None:
            update_data["addr"] = item.addr
        if item.type is not None:
            update_data["type"] = item.type
        if item.description is not None:
            update_data["description"] = item.description
        if item.os is not None:
            update_data["os"] = item.os
        update_data["updated_at"] = datetime.utcnow().isoformat()
        
        # Update item (user_id filter ensures user can only update their own items)
        response = supabase.table("CMDB").update(update_data).eq("tag_id", tag_id).eq("user_id", user_data["user_id"]).execute()
        
        return {"response": response}
    except Exception as e:
        if isinstance(e, HTTPException):
            raise e
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Database error: {str(e)}"
        )

# Delete CMDB item (only if it belongs to the authenticated user)
@app.delete("/cmdb/{tag_id}", response_model=dict)
async def delete_cmdb_item(tag_id: str, user_data: dict = Depends(verify_token)):
    try:
        # Check if item exists and belongs to this user
        existing = supabase.table("CMDB").select("*").eq("tag_id", tag_id).eq("user_id", user_data["user_id"]).execute()
        if not existing.data:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"CMDB item with tag_id {tag_id} not found or does not belong to you"
            )
        
        # Delete item (user_id filter ensures user can only delete their own items)
        response = supabase.table("CMDB").delete().eq("tag_id", tag_id).eq("user_id", user_data["user_id"]).execute()
        
        return {"response": response}
    except Exception as e:
        if isinstance(e, HTTPException):
            raise e
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Database error: {str(e)}"
        )

# Search CMDB items (only returns items that belong to the authenticated user)
@app.get("/cmdb/search/{query}", response_model=dict)
async def search_cmdb_items(query: str, user_data: dict = Depends(verify_token)):
    try:
        # Using ILIKE for case-insensitive search across multiple columns
        # And filtering by user_id for security
        response = supabase.table("CMDB").select("*, Users(*)").eq("user_id", user_data["user_id"]).or_(
            f"tag_id.ilike.%{query}%,ip.ilike.%{query}%,addr.ilike.%{query}%,type.ilike.%{query}%,description.ilike.%{query}%"
        ).execute()
        
        return {"response": response}
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Database error: {str(e)}"
        )

@app.post("/updateAWS")
async def update_aws_credentials(Aws: Aws, credentials: Annotated[HTTPAuthorizationCredentials, Depends(security)]):
    try:
        token = credentials.credentials
        res = jwt.decode(token, key=clerk_public_key, algorithms=['RS256'])
        mail = res['email']
        
        secret_auth_uri = "https://app.infisical.com/api/v1/auth/universal-auth/login"
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        auth_data = {
            "clientSecret": os.getenv('clientSecret'),
            "clientId": os.getenv('clientId')
        }
        
        # Get access token
        response = requests.post(url=secret_auth_uri, headers=headers, data=auth_data)
        response.raise_for_status()
        access_token = response.json()['accessToken']
        
        auth_headers = {
            'Authorization': f'Bearer {access_token}'
        }
        
        # Update AWS credentials
        aws_dict = {
            f"AWS_ACCESS_KEY_{mail}": Aws.access_key,
            f"AWS_SECRET_KEY_{mail}": Aws.secrete_access,
            f"AWS_REGION_{mail}": Aws.region
        }
        
        for key, value in aws_dict.items():
            url = f"https://us.infisical.com/api/v3/secrets/raw/{key}"
            payload = {
                "environment": "prod",
                "secretValue": value,
                "workspaceId": "113f5a41-dbc3-447d-8b3a-6fe8e9e6e99c"
            }
            
            headers = {
                "Authorization": auth_headers['Authorization'],
                "Content-Type": "application/json"
            }
            
            response = requests.request("POST", url, json=payload, headers=headers)
            
        return {"response": "AWS credentials updated successfully"}
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to update AWS credentials: {str(e)}"
        )

@app.post("/updateSSH")
async def update_ssh_credentials(ssh: ssh, credentials: Annotated[HTTPAuthorizationCredentials, Depends(security)]):
    try:
        token = credentials.credentials
        res = jwt.decode(token, key=clerk_public_key, algorithms=['RS256'])
        mail = res['email']
        
        secret_auth_uri = "https://app.infisical.com/api/v1/auth/universal-auth/login"
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        auth_data = {
            "clientSecret": os.getenv('clientSecret'),
            "clientId": os.getenv('clientId')
        }
        
        # Get access token
        response = requests.post(url=secret_auth_uri, headers=headers, data=auth_data)
        response.raise_for_status()
        access_token = response.json()['accessToken']
        
        auth_headers = {
            'Authorization': f'Bearer {access_token}'
        }
        
        # Update SSH key
        url = f"https://us.infisical.com/api/v3/secrets/raw/SSH_KEY_{mail}"
        payload = {
            "environment": "prod",
            "secretValue": ssh.key_file,
            "workspaceId": "113f5a41-dbc3-447d-8b3a-6fe8e9e6e99c"
        }
        
        headers = {
            "Authorization": auth_headers['Authorization'],
            "Content-Type": "application/json"
        }
        
        response = requests.request("POST", url, json=payload, headers=headers)
        return {"response": "SSH credentials updated successfully"}
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to update SSH credentials: {str(e)}"
        )

@app.post("/updateServiceNow")
async def update_servicenow_credentials(snow: Snow_key, credentials: Annotated[HTTPAuthorizationCredentials, Depends(security)]):
    try:
        token = credentials.credentials
        res = jwt.decode(token, key=clerk_public_key, algorithms=['RS256'])
        mail = res['email']
        
        secret_auth_uri = "https://app.infisical.com/api/v1/auth/universal-auth/login"
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        auth_data = {
            "clientSecret": os.getenv('clientSecret'),
            "clientId": os.getenv('clientId')
        }
        
        # Get access token
        response = requests.post(url=secret_auth_uri, headers=headers, data=auth_data)
        response.raise_for_status()
        access_token = response.json()['accessToken']
        
        auth_headers = {
            'Authorization': f'Bearer {access_token}'
        }
        
        # Update ServiceNow credentials
        snow_dict = {
            f"SNOW_KEY_{mail}": snow.snow_key,
            f"SNOW_INSTANCE_{mail}": snow.snow_instance,
            f"SNOW_USER_{mail}": snow.snow_user,
            f"SNOW_PASSWORD_{mail}": snow.snow_password
        }
        
        for key, value in snow_dict.items():
            url = f"https://us.infisical.com/api/v3/secrets/raw/{key}"
            payload = {
                "environment": "prod",
                "secretValue": value,
                "workspaceId": "113f5a41-dbc3-447d-8b3a-6fe8e9e6e99c"
            }
            
            headers = {
                "Authorization": auth_headers['Authorization'],
                "Content-Type": "application/json"
            }
            
            response = requests.request("POST", url, json=payload, headers=headers)
            
        return {"response": "ServiceNow credentials updated successfully"}
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to update ServiceNow credentials: {str(e)}"
        )

@app.post("/storeResult")
async def store_result(inc_number: str, result: str, credentials: Annotated[HTTPAuthorizationCredentials, Depends(security)]):
    try:
        token = credentials.credentials
        res = jwt.decode(token, key=clerk_public_key, algorithms=['RS256'])
        mail = res['email']
        
        # Get user_id from Users table
        user_response = supabase.table("Users").select("id").eq("email", mail).execute()
        if not user_response.data:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        user_id = user_response.data[0]["id"]
        
        # Store result in Results table
        response = supabase.table("Results").insert({
            "inc_number": inc_number,
            "description": result,
            "short_description": result,
            "user_id": user_id,
            "created_at": datetime.utcnow().isoformat()
        }).execute()
        
        return {"response": "Result stored successfully", "data": response.data}
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to store result: {str(e)}"
        )

@app.get("/getResults/{inc_number}")
async def get_results(inc_number: str, credentials: Annotated[HTTPAuthorizationCredentials, Depends(security)]):
    try:
        token = credentials.credentials
        res = jwt.decode(token, key=clerk_public_key, algorithms=['RS256'])
        mail = res['email']
        
        # Get user_id from Users table
        user_response = supabase.table("Users").select("id").eq("email", mail).execute()
        if not user_response.data:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        user_id = user_response.data[0]["id"]
        
        # Get results from Results table, ordered by creation date
        response = supabase.table("Results")\
            .select("description, created_at")\
            .eq("inc_number", inc_number)\
            .eq("user_id", user_id)\
            .order("created_at", desc=True)\
            .execute()
        
        return {"response": response}
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get results: {str(e)}"
        )

@app.post("/incidentAdd")
def incidentAdd(Req:Incident, user_data: dict = Depends(verify_token)):
    # Get user_id from verified token
    user_id = user_data.get('user_id')
    
    # Insert incident with user_id
    response = (
    supabase.table("Incidents")
    .insert({
        "id": Req.id, 
        "short_description": Req.short_description, 
        "tag_id": Req.tag_id, 
        "state": Req.state, 
        "inc_number": Req.inc_number,
        "user_id": user_id  # Add user_id to the incident
    })
    .execute()
    )
    
    # Get instance_id
    instance_id = supabase.table("Incidents").select("tag_id").eq("id", Req.id).execute()
    
    # Prepare SQS queue message
    sqsqueue = session.resource('sqs').get_queue_by_name(QueueName='infraaiqueue.fifo')
    message_body = json.dumps({
        "Aws": {
            "access_key": "",  # Will be retrieved by worker from user's stored credentials
            "secrete_access": "",
            "region": "",
            "instance_id": Req.tag_id  # Using tag_id as instance_id for now
        },
        "Mail": {
            "inc_number": Req.inc_number,
            "subject": Req.short_description,
            "message": f"Incident {Req.inc_number}: {Req.short_description}"
        },
        "Meta": {
            "user_id": user_id,
            "tag_id": Req.tag_id
        }
    })
    content_hash = hashlib.sha256(message_body.encode()).hexdigest()
    unique_id = f"{content_hash}-{uuid.uuid4().hex}"
    sqsqueue.send_message(
        MessageBody=message_body,
        MessageGroupId=(Req.inc_number or "infraai").strip()[:128],  # per-incident with safe fallback
        MessageDeduplicationId=unique_id
    )

    return {"response": {"user_id": user_id}}