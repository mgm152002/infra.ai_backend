# Use a slim Python base image for Ansible
FROM python:3.11-slim

# Metadata
LABEL maintainer="you@example.com" \
      description="Sandboxed environment for running Ansible scripts with AWS CLI"

# Install system dependencies for Ansible, SSH, and AWS CLI
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        sshpass \
        openssh-client \
        git \
        curl \
        unzip \
        groff \
        less \
        sudo \
        bash \
    && curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip" \
    && unzip awscliv2.zip \
    && ./aws/install --bin-dir /usr/local/bin --install-dir /usr/local/aws-cli \
    && rm -rf aws awscliv2.zip \
    && rm -rf /var/lib/apt/lists/*

# Install Ansible
RUN pip install --no-cache-dir ansible
RUN pip install --no-cache-dir ansible boto3 botocore

# Create a non-root user for sandboxing
RUN useradd -ms /bin/bash ansible && \
    echo "ansible ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/ansible

# Switch to non-root user
RUN mkdir -p /scripts && chown -R ansible:ansible /scripts
USER ansible
WORKDIR /scripts

# Prevent container from running as root inside
ENV ANSIBLE_CONFIG=/home/ansible/ansible.cfg
ENV PATH="$PATH:/usr/local/bin"

# Copy default ansible.cfg (limits execution to sandbox)
COPY ansible.cfg /home/ansible/ansible.cfg

# Copy playbooks (optional; otherwise mount them at runtime)
# COPY ./playbooks/ /home/ansible/playbooks/

# Verify AWS CLI + Ansible exist
RUN aws --version && ansible --version

# Entry point: run Ansible inside sandbox
ENTRYPOINT ["ansible-playbook"]