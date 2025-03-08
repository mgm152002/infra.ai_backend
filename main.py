from typing import Union
from fastapi import FastAPI ,File, UploadFile,Depends, Response, status,HTTPException
from fastapi import security
from pydantic import BaseModel
import google.generativeai as genai
import requests
import subprocess
from pinecone import Pinecone
import re
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
import jwt
import redis
from supabase import create_client, Client
from urllib.parse import urlencode
import json
import hashlib
from requests.auth import HTTPBasicAuth
import uuid
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from typing import Annotated
app = FastAPI()
security = HTTPBearer()
from langchain_google_genai import ChatGoogleGenerativeAI
import os
from dotenv import load_dotenv
import getpass
from langchain_core.tools import tool
from langchain.agents import initialize_agent, Tool
from langchain.memory import ConversationBufferMemory
from langchain.schema import HumanMessage
load_dotenv()
genai.configure(api_key=os.getenv('Gemini_Api_Key'))
pc = Pinecone(api_key="pcsk_WixB2_C6B8eWdCN9WaRuugDbqaGb5tRPVG8K8mpk7fWux2UesABstJxMMEcw8Smsz57eU")
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
model = init_chat_model("mistral-small-latest", model_provider="mistralai")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
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

lock = 0

queue=[]

# agent bacground

agent_bacground ='you are a l1 engineer responsible for basic troubleshooting so do basic troubleshooting if the issue is resolved even temporaraly its resolved you are also responsible for completeing basic service requests and if the issue is not resolved escalate it to l2 engineer'

# assistant = pc.assistant.create_assistant(
#     assistant_name="metalaiassistant", 
#     instructions="Answer directly and succinctly. Do not provide any additional information.", # Description or directive for the assistant to apply to all responses.
#     timeout=30 # Wait 30 seconds for assistant operation to complete.
# )



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
  
app.post("/addKnowledge")   
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


def askQuestion(question: str):
    msg = Message(content=question)
    assistant1 = pc.assistant.Assistant(
    assistant_name="metalaiassistant", 
    )
    resp = assistant1.chat(messages=[msg])
    return {"response": resp}



@app.post("/queueAdd")

def queueAdd(Req:RequestBody):
    queue.append({"Aws": Req.Aws, "Mail": Req.Mail})

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
    
@app.post("/uplaodSSH")
def uploadSSH(credentials: Annotated[HTTPAuthorizationCredentials, Depends(security)], file: UploadFile = File(...),):
    with open("key.pem", "wb") as buffer:
        buffer.write(file.file.read())
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
    with open("key.pem", "rb") as file:
        decoded_key = file.read().decode('utf-8')  # Decode bytes to string

    payload = {
    "environment": "prod",
    "secretValue": decoded_key,
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
@app.post("/incidentAdd")

def incidentAdd(Req:Incident):
    response = (
    supabase.table("Incidents")
    .insert({"id": Req.id, "short_description": Req.short_description, "tag_id": Req.tag_id, "state": Req.state, "inc_number": Req.inc_number})
    .execute()
    
)
    mail=r.get('userjwt')
    aws:Aws=getAwsKeys(mail=mail)
    instance_id=supabase.table("Incidents").select("tag_id").eq("id", Req.id).execute()
    #inc_number=supabase.table("Incidents").select("inc_number").eq("id", Req.id).execute()
    
    aws['response']['instance_id']=instance_id.data[0]['tag_id']
    mail:IncidentMail={"subject": Req.short_description, "message": Req.short_description,"inc_number": Req.inc_number}
    
    sqsqueue=session.resource('sqs').get_queue_by_name(QueueName='infraaiqueue.fifo')
    realaws=aws['response']
    message_body = json.dumps({
    
    "Aws": realaws, 
    "Mail": mail
})  
    content_hash = hashlib.sha256(message_body.encode()).hexdigest()
    unique_id = f"{content_hash}-{uuid.uuid4().hex}"
    sqsqueue.send_message(MessageBody=message_body, MessageGroupId='infraai',MessageDeduplicationId=unique_id)

    #queue.append({"Aws": aws["response"], "Mail": mail})

    print(queue)
    
   
    
    return{"response": {"Aws": aws ["response"], "Mail": mail}}



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
            'aws_access_key_id': requests.get(f'{base_url}/AWS_ACCESS_KEY?workspaceSlug=infraai-oqb-h&environment=prod', headers=auth_headers).json(),
            'aws_secret_access_key': requests.get(f'{base_url}/AWS_SECRET_KEY?workspaceSlug=infraai-oqb-h&environment=prod', headers=auth_headers).json(),
            'aws_region': requests.get(f'{base_url}/AWS_REGION?workspaceSlug=infraai-oqb-h&environment=prod', headers=auth_headers).json()
            
        }
        #print(aws_credentials)
     except :
        print("error")
     awskeys:Aws={"access_key": aws_credentials['aws_access_key_id']['secret']['secretValue'], "secrete_access": aws_credentials['aws_secret_access_key']['secret']['secretValue'], "region": aws_credentials['aws_region']['secret']['secretValue']}
     return{'response':awskeys}

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
        
     except :
        print("error")

@app.get("/getIncidentsDetails/{inc_number}")
def getIncidentsDetails(inc_number: str):
    response = supabase.from_("Results").select("description").eq("inc_number", inc_number).execute()
    return{"response": response}    

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

    
@app.get("/allIncidents")

def allIncidents():
    response = supabase.table("Incidents").select("*",count='exact').execute()
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


SERVICENOW_URL = "https://dev230113.service-now.com/api/now/table/incident"
HEADERS = {
    "Content-Type": "application/json",
    "x-sn-apikey": os.getenv("SNOW_KEY"),
}

@tool
def create_incident(create:Dict):
    """
    Create an incident in ServiceNow.
    """
    model = genai.GenerativeModel("gemini-2.0-flash-exp")
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
    parsed_json['urgency']=int(parsed_json['urgency'])
    parsed_json['impact']=int(parsed_json['impact'])
    response = requests.post(SERVICENOW_URL, json=parsed_json, headers=HEADERS)
    return response.json() if response.status_code == 201 else {"status": "failed", "message": response.text}

@tool
def update_incident(incident_number: str, updates: dict):

    """Update an incident using its incident number."""

    username="AutoDispacther"
    password="manojGM@123"
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



tools = [create_incident, update_incident]
llm_with_tools = model.bind_tools(tools)

tool_mapping = {"create_incident": create_incident, "update_incident": update_incident}

@app.post("/chat")
def chat(message:str):
    gemini = genai.GenerativeModel("gemini-2.0-flash-exp")
    messages=[HumanMessage(message)]
    res=llm_with_tools.invoke(messages)
    messages.append(res)
    for tool_call in res.tool_calls:
        tool = tool_mapping[tool_call["name"].lower()]
        tool_output = tool.invoke(tool_call["args"])
        messages.append(ToolMessage(tool_output, tool_call_id=tool_call["id"]))
        ex="successfully created the incident with the description or failed to create incident"
    result=gemini.generate_content(f"create a success or a failure message like {ex} message for this {messages} and return the incident number as well")
    llm_with_tools.invoke(messages)
    return({"result":res.tool_calls,"success/fail":result.parts[0].text})