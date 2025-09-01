pipeline {
    agent any
    
    environment {
        DOCKER_HUB_CREDS = credentials('docker-hub-token')
        VAULT_API_TOKEN = credentials('vault_key')
        SSH_KEY = credentials('platform_ssh_key')
        VAULT_SERVER_IP = "10.0.0.4"
        APP_SERVER_IP = "10.0.0.5"
        USER="azureuser"
    }
    
    stages {
        stage('Build and push to docker hub') {
            steps {
                git branch: 'main', url: 'https://github.com/mgm152002/infra.ai_backend.git'
                
                // Login to Docker Hub
                sh 'echo $DOCKER_HUB_CREDS | docker login -u mgm15 --password-stdin'
                
                // Build and push for linux/amd64
                sh '''
                    docker buildx build --platform linux/amd64 \
                    -t mgm15/infra.ai:$BUILD_NUMBER \
                    --push .
                '''
            }
            post {
                always {
                    sh "docker rmi mgm15/infra.ai:$BUILD_NUMBER || true"
                    sh "docker logout"
                }
            }
        }
        
        stage('Get Env File from Vault'){
           steps {
                // Get data from Vault and save to .env file
                sh '''
                    sudo curl -X GET https://${VAULT_SERVER_IP}:8200/v1/infra.ai/data/infra.ai \
                    -H "accept: application/json" \
                    -H "X-Vault-Token: $VAULT_API_TOKEN" \
                    -k > vault_response.json
                    
                    # Extract data from JSON response and create .env file
                    sudo cat vault_response.json | jq -r '.data.data | to_entries | .[] | "\\(.key)=\\(.value)"' > .env
                '''
                
                // Copy .env file to remote server
                sh '''
                    sudo scp -i $SSH_KEY -o StrictHostKeyChecking=no .env ${USER}@${APP_SERVER_IP}:/home/${USER}/.env
                '''
            }
        }
        
        stage('Deploy container on remote server'){
            steps{
                // Connect to remote server and execute docker commands
                sh '''
                    ssh -i $SSH_KEY -o StrictHostKeyChecking=no ${USER}@${APP_SERVER_IP} "
                        echo $DOCKER_HUB_CREDS | sudo docker login -u mgm15 --password-stdin
                        sudo docker rm -vf \\$(docker ps -aq)
                        sudo docker rmi -f \\$(docker images -aq)
                        sudo docker pull mgm15/infra.ai:$BUILD_NUMBER
                        sudo docker run -d --restart unless-stopped -p 8000:8000 --env-file /home/${USER}/.env mgm15/infra.ai:$BUILD_NUMBER
                        sudo docker logout
                        sudo rm -f .env
                    "
                '''
            }
        }
    }
}