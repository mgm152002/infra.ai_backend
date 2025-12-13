#!/bin/bash
set -e

# The BUCKET env var is passed from Lambda environment
BUCKET=${BUCKET:-"my-ansible-runtime-bucket"}

# Download runtime files from S3
aws s3 cp s3://${BUCKET}/ansible-runtime/ . --recursive

# Make scripts executable
chmod +x install_ansible_modules.sh playbook_command.sh

# Install Ansible modules if script exists
if [ -f install_ansible_modules.sh ]; then
    ./install_ansible_modules.sh
fi

# Run the playbook command if script exists
if [ -f playbook_command.sh ]; then
    ./playbook_command.sh
fi

# Clean up files
rm -f install_ansible_modules.sh playbook_command.sh inventory_file.ini playbook.yml vars.yml key.pem

echo "Ansible execution completed successfully"
exit 0