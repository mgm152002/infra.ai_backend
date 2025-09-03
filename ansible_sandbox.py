import boto3
import os
import time

# -------------------------------
# AWS CONFIG (Root credentials)
# -------------------------------
AWS_ACCESS_KEY = os.getenv("access_key")       # export access_key=...
AWS_SECRET_KEY = os.getenv("secrete_access")    # export secret_access=...
REGION = "ap-south-1"
ACCOUNT_ID = os.getenv("account_id", "")

BUCKET = "my-ansible-runtime-bucket"  # must exist already
CLUSTER_NAME = "ansible-runner-cluster"
TASK_DEF_NAME = "ansible-runner-task"
CONTAINER_NAME = "ansible-runner"
ECR_IMAGE = f"{ACCOUNT_ID}.dkr.ecr.{REGION}.amazonaws.com/ansible_runner:latest"

# -------------------------------
# AWS CLIENTS (no roles, root creds only)
# -------------------------------
ecs = boto3.client(
    "ecs",
    aws_access_key_id=AWS_ACCESS_KEY,
    aws_secret_access_key=AWS_SECRET_KEY,
    region_name=REGION,
)
logs = boto3.client(
    "logs",
    aws_access_key_id=AWS_ACCESS_KEY,
    aws_secret_access_key=AWS_SECRET_KEY,
    region_name=REGION,
)
s3 = boto3.client(
    "s3",
    aws_access_key_id=AWS_ACCESS_KEY,
    aws_secret_access_key=AWS_SECRET_KEY,
    region_name=REGION,
)
ec2 = boto3.client(
    "ec2",
    aws_access_key_id=AWS_ACCESS_KEY,
    aws_secret_access_key=AWS_SECRET_KEY,
    region_name=REGION,
)

# -------------------------------
# 1. Upload runtime files to S3
# -------------------------------
files = [
    "install_ansible_modules.sh",
    "playbook_command.sh",
    "inventory_file.ini",
    "playbook.yml",
    "vars.yml",
    "key.pem",
]

for f in files:
    s3.upload_file(f, BUCKET, f"ansible-runtime/{f}")
    print(f"Uploaded {f} to s3://{BUCKET}/ansible-runtime/{f}")

# -------------------------------
# 2. Register Task Definition (no taskRoleArn / executionRoleArn)
# -------------------------------
ecs.register_task_definition(
    family=TASK_DEF_NAME,
    requiresCompatibilities=["FARGATE"],
    cpu="512",
    memory="1024",
    networkMode="awsvpc",
    executionRoleArn=f"arn:aws:iam::{ACCOUNT_ID}:role/ecsTaskExecutionRole",  # REQUIRED
    containerDefinitions=[
        {
            "name": CONTAINER_NAME,
            "image": ECR_IMAGE,
            "entryPoint": ["/bin/sh", "-c"],
            "command": [
                f"aws s3 cp s3://{BUCKET}/ansible-runtime/ . --recursive && "
                "chmod +x install_ansible_modules.sh playbook_command.sh && "
                "./install_ansible_modules.sh && "
                "./playbook_command.sh && "
                "rm -f *"
            ],
            "environment": [
                {"name": "AWS_ACCESS_KEY_ID", "value": AWS_ACCESS_KEY},
                {"name": "AWS_SECRET_ACCESS_KEY", "value": AWS_SECRET_KEY},
                {"name": "AWS_DEFAULT_REGION", "value": REGION},
            ],
            "logConfiguration": {
                "logDriver": "awslogs",
                "options": {
                    "awslogs-group": "/ecs/ansible-runner",
                    "awslogs-region": REGION,
                    "awslogs-stream-prefix": "ecs",
                },
            },
            "essential": True,
        }
    ],
)

# -------------------------------
# 3. Ensure ECS Cluster exists
# -------------------------------
try:
    ecs.describe_clusters(clusters=[CLUSTER_NAME])
    print(f"ECS Cluster {CLUSTER_NAME} already exists")
except ecs.exceptions.ClusterNotFoundException:
    print(f"ECS Cluster {CLUSTER_NAME} not found. Creating...")
    ecs.create_cluster(clusterName=CLUSTER_NAME)
    print(f"ECS Cluster {CLUSTER_NAME} created successfully")

# -------------------------------
# 4. Get default VPC + Subnets
# -------------------------------
vpcs = ec2.describe_vpcs(Filters=[{"Name": "isDefault", "Values": ["true"]}])
default_vpc_id = vpcs["Vpcs"][0]["VpcId"]

subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [default_vpc_id]}])
subnet_ids = [s["SubnetId"] for s in subnets["Subnets"]]

# -------------------------------
# 5. Run ECS Task
# -------------------------------
response = ecs.run_task(
    cluster=CLUSTER_NAME,
    launchType="FARGATE",
    taskDefinition=TASK_DEF_NAME,
    count=1,
    networkConfiguration={
        "awsvpcConfiguration": {
            "subnets": subnet_ids,
            "assignPublicIp": "ENABLED",
        }
    },
)

task_arn = response["tasks"][0]["taskArn"]
print(f"Started ECS task: {task_arn}")

# -------------------------------
# 6. Wait for Completion
# -------------------------------
while True:
    task_status = ecs.describe_tasks(cluster=CLUSTER_NAME, tasks=[task_arn])
    status = task_status["tasks"][0]["lastStatus"]
    if status == "STOPPED":
        break
    print("Task still running...")
    time.sleep(10)

try:
    logs.create_log_group(logGroupName="/ecs/ansible-runner")
    print("Log group created: /ecs/ansible-runner")
except logs.exceptions.ResourceAlreadyExistsException:
    print("Log group already exists: /ecs/ansible-runner")

# -------------------------------
# 7. Fetch Logs from CloudWatch
# -------------------------------
log_group = "/ecs/ansible-runner"
streams = logs.describe_log_streams(
    logGroupName=log_group, orderBy="LastEventTime", descending=True, limit=1
)

if "logStreams" in streams and len(streams["logStreams"]) > 0:
    stream_name = streams["logStreams"][0]["logStreamName"]
    events = logs.get_log_events(logGroupName=log_group, logStreamName=stream_name)

    print("\n===== Ansible Output =====\n")
    for event in events["events"]:
        print(event["message"])
else:
    print("\n⚠️ No log streams found. The ECS task may have failed before logs were created.")
# -------------------------------
# 8. Clean up S3 runtime files
# -------------------------------
print("\nCleaning up S3 runtime files...")

objects = s3.list_objects_v2(Bucket=BUCKET, Prefix="ansible-runtime/")
if "Contents" in objects:
    delete_keys = {"Objects": [{"Key": obj["Key"]} for obj in objects["Contents"]]}
    s3.delete_objects(Bucket=BUCKET, Delete=delete_keys)
    print(f"Deleted {len(delete_keys['Objects'])} files from s3://{BUCKET}/ansible-runtime/")
else:
    print("No runtime files found in S3 to clean up.")
