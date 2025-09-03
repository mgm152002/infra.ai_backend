import os
import json
import subprocess
import tempfile
import shutil
import boto3


BUCKET = os.getenv("ANSIBLE_RUNTIME_BUCKET", "my-ansible-runtime-bucket")
REGION = os.getenv("AWS_REGION", os.getenv("AWS_DEFAULT_REGION", "ap-south-1"))

s3 = boto3.client("s3", region_name=REGION)


def _download_prefix(prefix: str, workdir: str) -> None:
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=BUCKET, Prefix=prefix):
        for obj in page.get("Contents", []):
            key = obj["Key"]
            rel = key[len(prefix):]
            if not rel:
                continue
            dst = os.path.join(workdir, rel)
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            s3.download_file(BUCKET, key, dst)


def _chmod_if_exists(path: str) -> None:
    if os.path.exists(path):
        os.chmod(path, 0o755)


def _run_scripts(workdir: str) -> dict:
    install_path = os.path.join(workdir, "install_ansible_modules.sh")
    playbook_path = os.path.join(workdir, "playbook_command.sh")

    _chmod_if_exists(install_path)
    _chmod_if_exists(playbook_path)

    install = subprocess.run(["bash", "-lc", "./install_ansible_modules.sh"], cwd=workdir, capture_output=True, text=True)
    play = subprocess.run(["bash", "-lc", "./playbook_command.sh"], cwd=workdir, capture_output=True, text=True)

    return {
        "install_rc": install.returncode,
        "install_out": install.stdout,
        "install_err": install.stderr,
        "play_rc": play.returncode,
        "play_out": play.stdout,
        "play_err": play.stderr,
    }


def lambda_handler(event, context):
    # SQS event with Records
    for record in event.get("Records", []):
        body = json.loads(record["body"]) if isinstance(record.get("body"), str) else record.get("body", {})
        prefix = body.get("s3_prefix")
        if not prefix:
            continue

        workdir = tempfile.mkdtemp()
        try:
            _download_prefix(prefix, workdir)
            result = _run_scripts(workdir)
            s3.put_object(Bucket=BUCKET, Key=f"{prefix}result.json", Body=json.dumps(result).encode("utf-8"))
        finally:
            shutil.rmtree(workdir, ignore_errors=True)

    return {"ok": True}


