"""Infrastructure automation and local infrastructure data tools."""

import json
import os
import re
import smtplib
import subprocess
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Dict, Optional

import boto3
import paramiko
import redis
import requests
from langchain_core.messages import HumanMessage, SystemMessage
from langchain_core.tools import tool
from requests.auth import HTTPBasicAuth

from app.core.database import supabase
from app.core.llm import call_llm, get_llm
from app.schemas.models import Aws, IncidentMail, Snow_key


redis_client = redis.Redis(host="localhost", port=6379, db=0)

r = redis_client

system_prompt = """your an expert ai engineer and can write ansible playbooks for aws
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
   - the sop or instructions you receive may include manual tasks such as going to cloud provider websites (for example the AWS console) and creating VMs/EC2 instances or other resources; instead of returning manual console steps you MUST automate these actions using the correct Ansible AWS modules.
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
        """

amazon_context = {
    "amis": [
        {
            "amazon_linux": "ami-00bb6a80f01f03502",
            "ubuntu": "ami-00bb6a80f01f03502",
            "rhel": "ami-02ddb77f8f93ca4ca",
            "suse": "ami-0da723ce59d9e80ab",
            "windows_server": "ami-05a00967f06885a63",
        }
    ],
    "vpc_id": "vpc-0b0f2397039aefca8",
    "subnet_id": "subnet-028fb8a226cdc8c98",
    "key_name": "latest",
}

agent_bacground = "you are a l1 engineer responsible for basic troubleshooting so do basic troubleshooting if the issue is resolved even temporaraly its resolved you are also responsible for completeing basic service requests and if the issue is not resolved escalate it to l2 engineer"


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
        return "Email sent successfully ." + message
    except Exception as e:
        print(f"Failed to send escalation email: {str(e)}")
        return "Failed to send escalation email."


def power_status_tool(Aws: Aws):
    """Executes the power status check and takes action based on the status."""
    # Use the shared OpenRouter LLM for reasoning about AWS assets

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

        # Use the LLM to process the instance status
        query = (
            f"From the given {aws_assets}, find the status and OS information of the instance with ID {Aws['instance_id']}. "
            "Just return the status  and  and not anything else."
        )
        status = call_llm(query).strip()
        query1 = (
            f"From the given {aws_assets}. "
            "Just return the public ipv4 information and not anything else dont include exta spaces quotes or escape charecters."
        )

        query2 = (
            f"From the given {aws_assets}, find the status and OS information of the instance with ID {Aws['instance_id']}. "
            "Just return the os and flavour of os like amazon linux or rhel form the  etc  and  and not anything else."
        )
        osinfo = call_llm(query2).strip()
        ipv4 = call_llm(query1).strip()

        (print(status, osinfo, ipv4[0:11]),)
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
                ec2.start_instances(InstanceIds=[Aws["instance_id"]])
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

        return {"status_and_os_info": status, "action": action, "ipv4": ipv4, "os": osinfo}

    except Exception as e:
        # Escalate in case of any unexpected errors
        send_escalation_email(
            subject="AWS Power Status Tool Error",
            message=f"An error occurred in the PowerStatusTool: {str(e)}",
            recipient="mgm15072002@gmail.com",
        )
        return {"status_and_os_info": "error", "action": f"Escalated due to error: {str(e)}"}


def selfHealing(Aws: Aws, Mail: IncidentMail):

    response1 = power_status_tool(Aws)
    print(response1)

    if "Instance has been started successfully." in response1["action"]:
        # known_erros=askQuestion(f"An incident has been recivied with the subject {Mail.subject} and message {Mail.message} and the instance has been started successfully and {response['status_and_os_info']} is the os from ih there is an information in the document give it")
        aicommands = call_llm(
            f"An incident has been recivied with the subject {Mail['subject']} and message {Mail['message']} and the instance has been started successfully generate commands to fix the issue just return the commands and {response1['os']} is the os give the username of it its based on on aws and the public ipv4 is {response1['ipv4']} ssh is already connected so skip it and fit all the things in as single line such as if high cpu usage combine both monitoring the process and killing it in a single command and dont use interactive commands your background is {agent_bacground}"
        )
        lock = 1
        res = execute_command(
            aicommands, response1["ipv4"], "ec2-user", Mail["subject"], Mail["inc_number"]
        )
        if "resolved" in res:
            lock = 0
            res = (
                supabase.table("Incidents")
                .update({"state": "Resolved"})
                .eq("inc_number", Mail["inc_number"])
                .execute()
            )
            supabase.table("")
            return {"response": "done", "output": res}
        elif "not resolved" in res:
            lock = 0
            res1 = (
                supabase.table("Incidents")
                .update({"state": "NotResolved"})
                .eq("inc_number", Mail["inc_number"])
                .execute()
            )
            return {"response": "not resolved"}
        elif "Email sent to L2 engineer" in res:
            lock = 0
            res2 = (
                supabase.table("Incidents")
                .update({"state": "Escalated"})
                .eq("inc_number", Mail["inc_number"])
                .execute()
            )
            return {"response": "done email sent to L2 engineer, output: " + res}
        else:
            lock = 0
            res2 = (
                supabase.table("Incidents")
                .update({"state": "Resolved"})
                .eq("inc_number", Mail["inc_number"])
                .execute()
            )

            return {"response": "done", "output": res}
    else:
        return {"response": "error"}


def execute_command(command: str, hostname: str, username: str, incident: str, inc_number: str):
    getSSHKeys(r.get("userjwt"))
    # res1 =model.generate_content(f"if the issue is resolved from this context {command}")

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
    command1 = call_llm(
        f"just return the command {command} so that it can be executed in a single line don't return anything else without any extra space or anything extra other than command don't convert it into script just return the command as string of multiline use multiple line separator ssh is already connected so skip it and fit all the things in as single line remove bash and remove ``` and if using pid wrap it with tripple quotes dont use interactive commands while using commands like top use -b for load based issues first check and then try to resolve it if its alright then dont try to resolve it or try to kill the process if its not resolved"
    )

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

    result1 = call_llm(
        f"with the given incident context {incident} and output of command run {output} command {full_command} if the incident is resolved just send resolved or send unresolved if the icident like cpu usage than if the cpu usage see load first has gone down at that point it is resolved same for disk and all load based issues your backgeound is {agent_bacground} even if its a temporary solution if the issue is fixed return resolved"
    )
    print(result1)

    # Interpret the output using the model

    # Check if the incident is resolved
    if "not resolved" in result1.lower():
        # Send an email to the L2 engineer
        send_mail_to_l2_engineer(command, output, error)
        return {"output": output, "error": error, "result": "Email sent to L2 engineer"}
    else:
        res = (
            supabase.table("Incidents")
            .update({"state": "Resolved"})
            .eq("inc_number", inc_number)
            .execute()
        )
        supabase.table("Results").insert(
            {"inc_number": inc_number, "description": output}
        ).execute()
        return {"output": output, "error": error, "result": result1}


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
    return "Email sent to L2 engineer" + command + output + error


def getAwsKeys(mail: str):
    secret_auth_uri = "https://app.infisical.com/api/v1/auth/universal-auth/login"

    # Proper headers format as a dictionary
    headers = {"Content-Type": "application/x-www-form-urlencoded"}

    # Proper data format for the authentication request
    auth_data = {"clientId": os.getenv("clientId"), "clientSecret": os.getenv("clientSecret")}

    try:
        # Get access token
        response = requests.post(url=secret_auth_uri, headers=headers, data=auth_data)
        response.raise_for_status()  # Raise exception for bad status codes
        access_token = response.json()["accessToken"]

        # Headers for subsequent requests
        auth_headers = {"Authorization": f"Bearer {access_token}"}

        # Get AWS credentials
        base_url = "https://us.infisical.com/api/v3/secrets/raw"
        aws_credentials = {
            "aws_access_key_id": requests.get(
                f"{base_url}/AWS_ACCESS_KEY_{mail}?workspaceSlug=infraai-oqb-h&environment=prod",
                headers=auth_headers,
            ).json(),
            "aws_secret_access_key": requests.get(
                f"{base_url}/AWS_SECRET_KEY_{mail}?workspaceSlug=infraai-oqb-h&environment=prod",
                headers=auth_headers,
            ).json(),
            "aws_region": requests.get(
                f"{base_url}/AWS_REGION_{mail}?workspaceSlug=infraai-oqb-h&environment=prod",
                headers=auth_headers,
            ).json(),
        }
        # print(aws_credentials)
    except:
        print("error")
    awskeys: Aws = {
        "access_key": aws_credentials["aws_access_key_id"][0]["secret"]["secretValue"],
        "secrete_access": aws_credentials["aws_secret_access_key"][0]["secret"]["secretValue"],
        "region": aws_credentials["aws_region"][0]["secret"]["secretValue"],
    }
    return {"response": awskeys}


def getSnowKeys(mail: str):
    secret_auth_uri = "https://app.infisical.com/api/v1/auth/universal-auth/login"

    # Proper headers format as a dictionary
    headers = {"Content-Type": "application/x-www-form-urlencoded"}

    # Proper data format for the authentication request
    auth_data = {"clientId": os.getenv("clientId"), "clientSecret": os.getenv("clientSecret")}

    try:
        # Get access token
        response = requests.post(url=secret_auth_uri, headers=headers, data=auth_data)
        response.raise_for_status()  # Raise exception for bad status codes
        access_token = response.json()["accessToken"]

        # Headers for subsequent requests
        auth_headers = {"Authorization": f"Bearer {access_token}"}

        # Get ServiceNow credentials
        base_url = "https://us.infisical.com/api/v3/secrets/raw"
        snow_credentials = {
            "snow_key": requests.get(
                f"{base_url}/SNOW_KEY_{mail}?workspaceSlug=infraai-oqb-h&environment=prod",
                headers=auth_headers,
            ).json(),
            "snow_instance": requests.get(
                f"{base_url}/SNOW_INSTANCE_{mail}?workspaceSlug=infraai-oqb-h&environment=prod",
                headers=auth_headers,
            ).json(),
            "snow_user": requests.get(
                f"{base_url}/SNOW_USER_{mail}?workspaceSlug=infraai-oqb-h&environment=prod",
                headers=auth_headers,
            ).json(),
            "snow_password": requests.get(
                f"{base_url}/SNOW_PASSWORD_{mail}?workspaceSlug=infraai-oqb-h&environment=prod",
                headers=auth_headers,
            ).json(),
        }
    except:
        print("error")

    snowkeys: Snow_key = {
        "snow_key": snow_credentials["snow_key"]["secret"]["secretValue"],
        "snow_instance": snow_credentials["snow_instance"]["secret"]["secretValue"],
        "snow_user": snow_credentials["snow_user"]["secret"]["secretValue"],
        "snow_password": snow_credentials["snow_password"]["secret"]["secretValue"],
    }

    return {"response": snowkeys}


def getSnowKeys(mail: str):
    secret_auth_uri = "https://app.infisical.com/api/v1/auth/universal-auth/login"

    # Proper headers format as a dictionary
    headers = {"Content-Type": "application/x-www-form-urlencoded"}

    # Proper data format for the authentication request
    auth_data = {"clientSecret": os.getenv("clientSecret"), "clientId": os.getenv("clientId")}

    try:
        # Get access token
        response = requests.post(url=secret_auth_uri, headers=headers, data=auth_data)
        response.raise_for_status()  # Raise exception for bad status codes
        access_token = response.json()["accessToken"]

        # Headers for subsequent requests
        auth_headers = {"Authorization": f"Bearer {access_token}"}

        # Get ServiceNow credentials
        base_url = "https://us.infisical.com/api/v3/secrets/raw"
        snow_credentials = {
            "snow_key": requests.get(
                f"{base_url}/SNOW_KEY_{mail}?workspaceSlug=infraai-oqb-h&environment=prod",
                headers=auth_headers,
            ).json(),
            "snow_instance": requests.get(
                f"{base_url}/SNOW_INSTANCE_{mail}?workspaceSlug=infraai-oqb-h&environment=prod",
                headers=auth_headers,
            ).json(),
            "snow_user": requests.get(
                f"{base_url}/SNOW_USER_{mail}?workspaceSlug=infraai-oqb-h&environment=prod",
                headers=auth_headers,
            ).json(),
            "snow_password": requests.get(
                f"{base_url}/SNOW_PASSWORD_{mail}?workspaceSlug=infraai-oqb-h&environment=prod",
                headers=auth_headers,
            ).json(),
        }
    except:
        print("error")

    snowkeys: Snow_key = {
        "snow_key": snow_credentials["snow_key"]["secret"]["secretValue"],
        "snow_instance": snow_credentials["snow_instance"]["secret"]["secretValue"],
        "snow_user": snow_credentials["snow_user"]["secret"]["secretValue"],
        "snow_password": snow_credentials["snow_password"]["secret"]["secretValue"],
    }

    return {"response": snowkeys}


def getSSHKeys(mail: str):
    secret_auth_uri = "https://app.infisical.com/api/v1/auth/universal-auth/login"

    # Proper headers format as a dictionary
    headers = {"Content-Type": "application/x-www-form-urlencoded"}

    # Proper data format for the authentication request
    auth_data = {"clientSecret": os.getenv("clientSecret"), "clientId": os.getenv("clientId")}

    try:
        # Get access token
        response = requests.post(url=secret_auth_uri, headers=headers, data=auth_data)
        response.raise_for_status()  # Raise exception for bad status codes
        access_token = response.json()["accessToken"]

        # Headers for subsequent requests
        auth_headers = {"Authorization": f"Bearer {access_token}"}

        # Get AWS credentials
        base_url = "https://us.infisical.com/api/v3/secrets/raw"
        sshkey = (
            requests.get(
                f"{base_url}/SSH_KEY_{mail}?workspaceSlug=infraai-oqb-h&environment=prod",
                headers=auth_headers,
            ).json(),
        )

        with open("key.pem", "wb") as file:
            file.write(sshkey[0]["secret"]["secretValue"].encode("utf-8"))
        return {"key_file": sshkey[0]["secret"]["secretValue"]}
    except:
        print("error")


def getAwsKeys(mail: str):
    secret_auth_uri = "https://app.infisical.com/api/v1/auth/universal-auth/login"

    # Proper headers format as a dictionary
    headers = {"Content-Type": "application/x-www-form-urlencoded"}

    # Proper data format for the authentication request
    auth_data = {"clientSecret": os.getenv("clientSecret"), "clientId": os.getenv("clientId")}

    try:
        # Get access token
        response = requests.post(url=secret_auth_uri, headers=headers, data=auth_data)
        response.raise_for_status()  # Raise exception for bad status codes
        access_token = response.json()["accessToken"]

        # Headers for subsequent requests
        auth_headers = {"Authorization": f"Bearer {access_token}"}

        # Get AWS credentials
        base_url = "https://us.infisical.com/api/v3/secrets/raw"
        aws_credentials = {
            "aws_access_key_id": requests.get(
                f"{base_url}/AWS_ACCESS_KEY_{mail}?workspaceSlug=infraai-oqb-h&environment=prod",
                headers=auth_headers,
            ).json(),
            "aws_secret_access_key": requests.get(
                f"{base_url}/AWS_SECRET_KEY_{mail}?workspaceSlug=infraai-oqb-h&environment=prod",
                headers=auth_headers,
            ).json(),
            "aws_region": requests.get(
                f"{base_url}/AWS_REGION_{mail}?workspaceSlug=infraai-oqb-h&environment=prod",
                headers=auth_headers,
            ).json(),
        }
        print(aws_credentials)
    except:
        print("error")
    awskeys: Aws = {
        "access_key": aws_credentials["aws_access_key_id"]["secret"]["secretValue"],
        "secrete_access": aws_credentials["aws_secret_access_key"]["secret"]["secretValue"],
        "region": aws_credentials["aws_region"]["secret"]["secretValue"],
    }
    return {"response": awskeys}


def get_sys_id(mapping: dict, key: str) -> str:
    """Retrieve the sys_id from a given mapping dictionary."""
    return mapping.get(key, "")


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
    "state": {"new": 1, "in_progress": 2, "on_hold": 3, "resolved": 6, "closed": 7, "canceled": 8},
    "impact": {"low": 3, "medium": 2, "high": 1},
    "urgency": {"low": 3, "medium": 2, "high": 1},
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
        "User error": "User error",
    },
    "close_notes": {"provide notes while closing or updating the incident"},
    "work_notes": {"provide notes while closing or updating the incident"},
}


@tool
def create_incident(create: Dict, mail: str):
    """Create an incident in ServiceNow for the authenticated user.

    The `mail` parameter is the user's internal email identifier supplied by the backend.
    Never ask the user to provide or confirm this value; assume the backend injects the
    correct `mail` when the tool is called and do not mention it in responses.
    """

    body = call_llm(
        f"this is the update I want to do to the incident {create}, this is the sysid and other mappings {sys_id_mapping} generate a body to send to rest api dont do anything else just give the json dont add backticks or json in the result come up with an urgence and impact value based on priority keep the as numbers only fill short_description and description as well"
    )
    match = re.search(r"\{.*\}", body, re.DOTALL)
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

    SERVICENOW_URL = getSnowKeys(mail=mail)["response"]["snow_instance"] + "/api/now/table/incident"
    HEADERS = {
        "Content-Type": "application/json",
        "x-sn-apikey": getSnowKeys(mail=mail)["response"]["snow_key"],
    }
    parsed_json["urgency"] = int(parsed_json["urgency"])
    parsed_json["impact"] = int(parsed_json["impact"])
    response = requests.post(SERVICENOW_URL, json=parsed_json, headers=HEADERS)
    return (
        response.json()
        if response.status_code == 201
        else {"status": "failed", "message": response.text}
    )


@tool
def update_incident(incident_number: str, updates: dict, mail: str):
    """Update a ServiceNow incident for the authenticated user using its incident number.

    The `mail` parameter is injected by the backend and must never be requested from
    the user. Do not mention this parameter or internal emails in model responses.
    """
    Snow_res = getSnowKeys(mail=mail)
    SERVICENOW_URL = Snow_res["response"]["snow_instance"] + "/api/now/table/incident"
    HEADERS = {
        "Content-Type": "application/json",
        "x-sn-apikey": getSnowKeys(mail=mail)["response"]["snow_key"],
    }

    username = Snow_res["response"]["snow_user"]
    password = Snow_res["response"]["snow_password"]
    body = call_llm(
        f"this is the update I want to do to the incident {updates}, this is the sysid and other mappings {sys_id_mapping} generate a body to send to rest api dont do anything else just give the json dont add backticks or json in the result come up with an urgence and impact value based on priority keep them as number only and when i am closing the incident include close_code and clouser_notes should have the following format clouser_notes:the clouser notes provided add work_notes to this while updating an incident"
    )
    # resnew=model.generate_content(f"add work_notes to this {res} if the inicdent is being closed generate a body to send to rest api dont do anything else")
    match = re.search(r"\{.*\}", body, re.DOTALL)
    if match:
        json_data = match.group()
        parsed_json = json.loads(json_data)  # Convert to dictionary if needed
        print(parsed_json)  #

        Updateurl = SERVICENOW_URL + f"?sysparm_limit=10&number={incident_number}"

    response = requests.get(Updateurl, headers=HEADERS, auth=HTTPBasicAuth(username, password))
    # if response.status_code != 200 or "result" not in response.json():
    #     return {"status": "failed", "message": "Incident not found"}
    # print(response.json())
    incident_sys_id = response.json()["result"][0]["sys_id"]
    update_url = f"{SERVICENOW_URL}/{incident_sys_id}"

    response = requests.patch(update_url, json=parsed_json, headers=HEADERS)
    return (
        response.json()
        if response.status_code == 200
        else {"status": "failed", "message": response.text}
    )


@tool
def get_incident_details(incident_number: str, mail: str):
    """Retrieve incident details from ServiceNow using the incident number.

    The `mail` parameter is injected by the backend and must never be requested from
    the user. Do not mention this parameter or internal emails in model responses.
    """
    Snow_res = getSnowKeys(mail=mail)
    SERVICENOW_URL = Snow_res["response"]["snow_instance"] + "/api/now/table/incident"
    HEADERS = {
        "Content-Type": "application/json",
        "x-sn-apikey": getSnowKeys(mail=mail)["response"]["snow_key"],
    }

    username = Snow_res["response"]["snow_user"]
    password = Snow_res["response"]["snow_password"]

    # Construct the URL with query parameter to find the incident by number
    query_url = f"{SERVICENOW_URL}?sysparm_limit=10&number={incident_number}"

    # Send GET request to ServiceNow API with basic authentication
    response = requests.get(query_url, headers=HEADERS, auth=HTTPBasicAuth(username, password))

    # Check if request was successful and results were found
    # Check if request was successful and results were found
    try:
        if response.status_code == 200:
            data = response.json()
            if "result" in data and data["result"]:
                # Return the full incident details
                return data["result"][0]
            else:
                return {"status": "failed", "message": "Incident not found in ServiceNow."}
        else:
            return {
                "status": "failed",
                "message": f"ServiceNow API Error: {response.status_code} - {response.text}",
            }
    except Exception as e:
        return {
            "status": "failed",
            "message": f"Failed to parse ServiceNow response: {str(e)}. Response text: {response.text[:200]}",
        }


@tool
def list_local_incidents(status: Optional[str] = None, limit: int = 20, mail: str = ""):
    """List incidents from the local database (not ServiceNow).

    Use this tool to query incidents stored in Supabase/PostgreSQL.

    Args:
        status: Filter by incident status (e.g., 'Queued', 'InProgress', 'Resolved', 'Closed')
        limit: Maximum number of incidents to return (default 20)
        mail: The user's email (injected by backend)
    """
    try:
        user_response = supabase.table("Users").select("id").eq("email", mail).execute()
        if not user_response.data:
            return {"status": "error", "message": "User not found"}
        user_id = user_response.data[0]["id"]

        query = (
            supabase.table("Incidents")
            .select("*, Users(*)")
            .eq("user_id", user_id)
            .order("created_at", desc=True)
            .limit(limit)
        )

        if status:
            query = query.eq("state", status)

        response = query.execute()
        return {"status": "ok", "incidents": response.data}
    except Exception as e:
        return {"status": "error", "message": str(e)}


@tool
def get_local_incident_details(inc_number: str, mail: str = ""):
    """Get details of a specific incident from local database by incident number.

    Args:
        inc_number: The incident number (e.g., 'INC-12345')
        mail: The user's email (injected by backend)
    """
    try:
        user_response = supabase.table("Users").select("id").eq("email", mail).execute()
        if not user_response.data:
            return {"status": "error", "message": "User not found"}
        user_id = user_response.data[0]["id"]

        response = (
            supabase.table("Incidents")
            .select("*, Users(*)")
            .eq("inc_number", inc_number)
            .eq("user_id", user_id)
            .execute()
        )

        if not response.data:
            return {"status": "not_found", "message": f"Incident {inc_number} not found"}

        return {"status": "ok", "incident": response.data[0]}
    except Exception as e:
        return {"status": "error", "message": str(e)}


@tool
def update_local_incident(inc_number: str, updates: dict, mail: str = ""):
    """Update a local incident in the database.

    Args:
        inc_number: The incident number to update
        updates: Dictionary of fields to update (e.g., {'state': 'InProgress', 'short_description': 'New description'})
        mail: The user's email (injected by backend)
    """
    try:
        user_response = supabase.table("Users").select("id").eq("email", mail).execute()
        if not user_response.data:
            return {"status": "error", "message": "User not found"}
        user_id = user_response.data[0]["id"]

        # Check if incident exists and belongs to user
        existing = (
            supabase.table("Incidents")
            .select("id")
            .eq("inc_number", inc_number)
            .eq("user_id", user_id)
            .execute()
        )
        if not existing.data:
            return {"status": "not_found", "message": f"Incident {inc_number} not found"}

        # Add updated_at timestamp
        updates["updated_at"] = datetime.utcnow().isoformat()

        response = (
            supabase.table("Incidents")
            .update(updates)
            .eq("inc_number", inc_number)
            .eq("user_id", user_id)
            .execute()
        )

        return {
            "status": "ok",
            "message": f"Incident {inc_number} updated successfully",
            "incident": response.data[0],
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}


@tool
def get_local_cmdb_count(mail: str = ""):
    """Get the total count of CMDB items and services for the authenticated user.

    Use this to answer questions about "total number of services", "how many hosts", etc.

    Args:
        mail: The user's email (injected by backend)
    """
    try:
        user_response = supabase.table("Users").select("id").eq("email", mail).execute()
        if not user_response.data:
            return {
                "status": "error",
                "message": "User not found",
                "total_cmdb_items": 0,
                "total_services": 0,
                "items_by_type": {},
            }
        user_id = user_response.data[0]["id"]

        # Get total count of CMDB items for this user
        response = (
            supabase.table("CMDB").select("id", count="exact").eq("user_id", user_id).execute()
        )
        total_items = response.count or 0

        # Get count by type
        type_response = supabase.table("CMDB").select("type").eq("user_id", user_id).execute()
        type_counts = {}
        for item in type_response.data or []:
            item_type = item.get("type", "unknown")
            type_counts[item_type] = type_counts.get(item_type, 0) + 1

        # Get services count (global, not user-specific)
        services_response = supabase.table("services").select("id", count="exact").execute()
        total_services = services_response.count or 0

        # Get all services for display
        services_list = supabase.table("services").select("*").execute()
        services = services_list.data or []

        return {
            "status": "ok",
            "total_cmdb_items": total_items,
            "total_services": total_services,
            "items_by_type": type_counts,
            "services": [
                {"id": s["id"], "name": s["name"], "service_type": s.get("service_type")}
                for s in services
            ],
        }
    except Exception as e:
        return {
            "status": "error",
            "message": str(e),
            "total_cmdb_items": 0,
            "total_services": 0,
            "items_by_type": {},
        }


@tool
def search_local_cmdb(query: str, mail: str = ""):
    """Search the local CMDB database for configuration items.

    Args:
        query: Search query (searches tag_id, IP, address, description, OS, type). Use empty string to get all items.
        mail: The user's email (injected by backend)
    """
    try:
        user_response = supabase.table("Users").select("id").eq("email", mail).execute()
        if not user_response.data:
            return {"status": "error", "message": "User not found", "items": [], "services": []}
        user_id = user_response.data[0]["id"]

        # Get services (global, not user-specific)
        services_response = supabase.table("services").select("*").execute()
        services = services_response.data or []

        # If query is empty, return all items
        if not query or not query.strip():
            response = supabase.table("CMDB").select("*, Users(*)").eq("user_id", user_id).execute()
        else:
            response = (
                supabase.table("CMDB")
                .select("*, Users(*)")
                .eq("user_id", user_id)
                .or_(
                    f"tag_id.ilike.%{query}%,ip.ilike.%{query}%,addr.ilike.%{query}%,type.ilike.%{query}%,description.ilike.%{query}%,os.ilike.%{query}%"
                )
                .execute()
            )

        items = response.data or []

        # Format items for better display
        formatted_items = []
        for item in items:
            formatted_items.append(
                {
                    "tag_id": item.get("tag_id", "N/A"),
                    "ip": item.get("ip", "N/A"),
                    "fqdn": item.get("fqdn", "N/A"),
                    "type": item.get("type", "N/A"),
                    "os": item.get("os", "N/A"),
                    "addr": item.get("addr", "N/A"),
                    "description": item.get("description", "N/A"),
                    "service_id": item.get("service_id", ""),
                    "source": item.get("source", "manual"),
                }
            )

        # Get service names for mapping
        service_map = {s["id"]: s["name"] for s in services}

        # Add service name to items
        for item in formatted_items:
            if item.get("service_id") and item["service_id"] in service_map:
                item["service_name"] = service_map[item["service_id"]]
            else:
                item["service_name"] = "Unassigned"

        return {
            "status": "ok",
            "items": formatted_items,
            "count": len(formatted_items),
            "services": services,
            "total_services": len(services),
        }
    except Exception as e:
        return {
            "status": "error",
            "message": str(e),
            "items": [],
            "services": [],
            "total_services": 0,
        }


@tool
def get_local_cmdb_item(tag_id: str, mail: str = ""):
    """Get a specific CMDB item by tag_id from local database.

    Args:
        tag_id: The tag_id of the configuration item
        mail: The user's email (injected by backend)
    """
    try:
        user_response = supabase.table("Users").select("id").eq("email", mail).execute()
        if not user_response.data:
            return {"status": "error", "message": "User not found"}
        user_id = user_response.data[0]["id"]

        response = (
            supabase.table("CMDB")
            .select("*, Users(*)")
            .eq("tag_id", tag_id)
            .eq("user_id", user_id)
            .execute()
        )

        if not response.data:
            return {"status": "not_found", "message": f"CMDB item {tag_id} not found"}

        return {"status": "ok", "item": response.data[0]}
    except Exception as e:
        return {"status": "error", "message": str(e)}
    """Fetch CMDB details for a host belonging to the authenticated user.

    The `mail` parameter is injected by the backend and must never be requested from
    the user. Do not mention this parameter or internal emails in model responses.

    The `tag_id` should match the host's tag identifier stored in the CMDB.
    """
    try:
        user_response = supabase.table("Users").select("id").eq("email", mail).execute()
        if not user_response.data:
            return {
                "status": "not_found",
                "message": f"User with email '{mail}' not found.",
                "items": [],
            }
        user_id = user_response.data[0]["id"]

        cmdb_response = (
            supabase.table("CMDB").select("*").eq("tag_id", tag_id).eq("user_id", user_id).execute()
        )

        items = cmdb_response.data or []

        if not items:
            return {
                "status": "not_found",
                "message": f"No CMDB entry found for tag_id '{tag_id}' for this user.",
                "items": [],
            }

        return {
            "status": "ok",
            "items": items,
        }
    except Exception as e:
        return {
            "status": "error",
            "message": str(e),
        }


@tool
def getfromcmdb(tag_id: str, mail: str):
    """Fetch CMDB details for a host belonging to the authenticated user.

    The `mail` parameter is injected by the backend and must never be requested from
    the user. Do not mention this parameter or internal emails in model responses.

    The `tag_id` should match the host's tag identifier stored in the CMDB.
    """
    try:
        user_response = supabase.table("Users").select("id").eq("email", mail).execute()
        if not user_response.data:
            return {
                "status": "not_found",
                "message": f"User with email '{mail}' not found.",
                "items": [],
            }
        user_id = user_response.data[0]["id"]

        cmdb_response = (
            supabase.table("CMDB").select("*").eq("tag_id", tag_id).eq("user_id", user_id).execute()
        )

        items = cmdb_response.data or []

        if not items:
            return {
                "status": "not_found",
                "message": f"No CMDB entry found for tag_id '{tag_id}' for this user.",
                "items": [],
            }

        return {
            "status": "ok",
            "items": items,
        }
    except Exception as e:
        return {
            "status": "error",
            "message": str(e),
        }


@tool
def search_cmdb(query: str, mail: str):
    """Search for configuration items in the CMDB using a keyword query.

    Use this when the user asks about a server/asset by name, IP, or description but doesn't provide a specific tag ID.
    The `mail` parameter is injected by the backend.
    """
    try:
        user_response = supabase.table("Users").select("id").eq("email", mail).execute()
        if not user_response.data:
            return {"status": "error", "message": "User not found"}
        user_id = user_response.data[0]["id"]

        response = (
            supabase.table("CMDB")
            .select("*")
            .eq("user_id", user_id)
            .or_(
                f"tag_id.ilike.%{query}%,ip.ilike.%{query}%,addr.ilike.%{query}%,type.ilike.%{query}%,description.ilike.%{query}%"
            )
            .execute()
        )

        return {"status": "ok", "items": response.data}
    except Exception as e:
        return {"status": "error", "message": str(e)}


@tool
def infra_automation_ai(message: str, mail: str):
    """Automate infrastructure-related tasks for the authenticated user.

    Use this tool whenever the user request or SOP describes infrastructure changes or
    manual operational steps (for example: "install docker on this EC2 instance",
    "go to the AWS console and create a VM", or "SSH to the server and run these
    commands"). The tool converts those instructions into Ansible-based automation
    and executes them in the user's AWS environment.

    The `mail` parameter is the backend-supplied user email identifier used to resolve
    Infisical / AWS / ServiceNow credentials. Never ask the user to provide or confirm
    this email; assume the backend passes the correct value and do not mention it in
    responses.
    """
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
    llm = get_llm()
    messages = [
        SystemMessage(
            content=f"""You are an expert AWS/Ansible automation engineer.

Your ONLY job is to generate deterministic Ansible automation artifacts in a strict, machine-parseable format. Always obey all of the rules below; never change the structure or add commentary.

ANSIBLE OUTPUT CONTRACT (DO NOT CHANGE):
{system_prompt}

ADDITIONAL HARD REQUIREMENTS:
- Always output ALL four sections <shell_commands>, <inventory_file>, <playbook>, <playbook_run_command> exactly once each, in that exact order.
- Do NOT output anything outside those tags (no explanations, markdown, backticks, or extra text).
- All shell content must be non-interactive (no prompts or confirmations).
- The playbook YAML must be syntactically valid, complete, and include all tasks required by the request.
- Never use placeholders or truncate code; always return full file contents.
- Treat any failure to follow this format as a critical error and correct yourself within the same response.

AWS CONTEXT (USE WHEN NEEDED, DO NOT MODIFY KEYS/VALUES):
{amazon_context}

GENERAL BEHAVIOR:
- Prefer safe, conservative defaults when something is ambiguous, but always stay within the above contract.
- If the user request conflicts with these rules, follow these system rules first.
"""
        ),
        HumanMessage(content=message),
    ]
    ai_msg = llm.invoke(messages)
    infra_ai = ai_msg.content
    # Extract shell commands
    shell_commands_match = re.search(r"<shell_commands>(.*?)</shell_commands>", infra_ai, re.DOTALL)
    if shell_commands_match:
        sections["shell_commands"] = shell_commands_match.group(1).strip()

    # Extract inventory file
    inventory_match = re.search(r"<inventory_file>(.*?)</inventory_file>", infra_ai, re.DOTALL)
    if inventory_match:
        sections["inventory_file"] = inventory_match.group(1).strip()

    # Extract playbook
    playbook_match = re.search(r"<playbook>(.*?)</playbook>", infra_ai, re.DOTALL)
    if playbook_match:
        sections["playbook"] = playbook_match.group(1).strip()
    playbook_command_match = re.search(
        r"<playbook_run_command>(.*?)</playbook_run_command>", infra_ai, re.DOTALL
    )
    if playbook_command_match:
        sections["playbook_command"] = playbook_command_match.group(1).strip()
    files_created = []
    getSSHKeys(mail=mail)
    subprocess.run("chmod 600 key.pem", shell=True)

    if "shell_commands" in sections:
        with open("install_ansible_modules.sh", "w") as f:
            f.write(sections["shell_commands"])
        os.chmod("install_ansible_modules.sh", 0o755)  # Make the shell script executable
        files_created.append("install_ansible_modules.sh")

    if "inventory_file" in sections:
        with open("inventory_file.ini", "w") as f:
            f.write(sections["inventory_file"])
        files_created.append("inventory_file.ini")

    if "playbook" in sections:
        with open("playbook.yml", "w") as f:
            f.write(sections["playbook"])
        files_created.append("playbook.yml")
    if "playbook_command" in sections:
        with open("playbook_command.sh", "w") as f:
            f.write(sections["playbook_command"])
            os.chmod("playbook_command.sh", 0o755)
        files_created.append("playbook_command.sh")

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

    # shell_output = subprocess.run("./install_ansible_modules.sh", shell=True, capture_output=True, text=True)
    # playbook_output=subprocess.run("./playbook_command.sh", shell=True,capture_output=True, text=True)
    playbook_output = subprocess.run(
        ["python3", "ansible_sandbox.py"], capture_output=True, text=True
    )
    print(playbook_output.stdout)
    print(playbook_output.stderr)
    os.remove("install_ansible_modules.sh")
    os.remove("inventory_file.ini")
    os.remove("playbook.yml")
    os.remove("vars.yml")
    os.remove("key.pem")
    os.remove("playbook_command.sh")

    return {"playbook_output": playbook_output.stdout, "playbook_eror": playbook_output.stderr}
