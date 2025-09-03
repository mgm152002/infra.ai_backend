FROM public.ecr.aws/lambda/python:3.11

# Install Ansible and AWS CLI dependencies
RUN pip install --no-cache-dir ansible boto3 awscli

# Copy handler
COPY handler.py ${LAMBDA_TASK_ROOT}/handler.py

# Lambda entry
CMD ["handler.lambda_handler"]


