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
    """
    Download all objects from the configured S3 bucket under the given prefix into a local workspace, preserving the prefix's relative path structure.
    
    The function lists objects under BUCKET with the provided Prefix, skips the object whose key equals the prefix itself, creates any needed subdirectories under workdir, and downloads each object into workdir at the path corresponding to the key suffix after the prefix.
    
    Parameters:
        prefix (str): S3 key prefix to download (objects with keys starting with this string).
        workdir (str): Local directory to place downloaded objects; directory structure under workdir mirrors the S3 key suffixes.
    """
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
    """
    Ensure the given filesystem path is executable (mode 0o755) if it exists.
    
    This function checks whether `path` exists and, when it does, sets its permission bits to 0o755 (rwxr-xr-x), making it executable by the owner and readable/executable by group and others.
    
    Parameters:
        path (str): Filesystem path to check and modify if present.
    """
    if os.path.exists(path):
        os.chmod(path, 0o755)


def _run_scripts(workdir: str) -> dict:
    """
    Run two workspace scripts (install_ansible_modules.sh then playbook_command.sh) if present, and capture their exit codes and outputs.
    
    This makes the two script files executable when they exist in the provided workdir, executes them sequentially in that directory using `bash -lc`, and returns a summary of their return codes, stdout, and stderr.
    
    Parameters:
        workdir (str): Filesystem path containing the scripts to run.
    
    Returns:
        dict: Keys:
            - install_rc (int): exit code of install_ansible_modules.sh
            - install_out (str): stdout from install_ansible_modules.sh
            - install_err (str): stderr from install_ansible_modules.sh
            - play_rc (int): exit code of playbook_command.sh
            - play_out (str): stdout from playbook_command.sh
            - play_err (str): stderr from playbook_command.sh
    """
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
    """
    AWS Lambda entry point that processes SQS records pointing to an S3 prefix.
    
    For each record in event["Records"] (SQS format) this handler:
    - Parses the record body (JSON string or dict) and reads "s3_prefix".
    - Creates a temporary working directory, downloads all objects under that S3 prefix into it, makes and runs two scripts found there (install_ansible_modules.sh and playbook_command.sh), collects their exit codes and output, and uploads a JSON summary to S3 at <prefix>result.json.
    - Always removes the temporary working directory. Any exceptions raised during download, execution, or upload propagate out of the function (the temp directory is still cleaned up).
    
    Parameters:
        event: AWS Lambda event payload; expects SQS-style Records where each record's body contains an "s3_prefix".
        context: Lambda context object (unused).
    
    Returns:
        dict: {"ok": True} when processing completes (note: exceptions may still be raised for individual failures).
    """
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


