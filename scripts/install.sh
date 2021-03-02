#!/bin/bash

#!/bin/bash
echo "=== Configuration Report ==="
echo "= Clean: [${Clean}]"
echo "= GitBehavior: [${GitBehavior}]"
echo "= GitCheckoutBranch: [${GitCheckoutBranch}]"
echo "= HostConfiguration: [${HostConfiguration}]"
echo "= LoadProductionDB: [${LoadProductionDB}]"
echo "==="


if [[ -z "$HostConfiguration" ]]; then
        echo "This script requires the \$HostConfiguration variable.  \$HostConfiguration must point to a directory of server-specific service XML files."
        exit 1
fi


 
echo "#!/bin/bash" >> /tmp/deploy-apps-${BUILD_NUMBER}.sh
echo "SourceHost=\"build-c6b.intelepeer.net\"" >> /tmp/deploy-apps-${BUILD_NUMBER}.sh
echo "SourceRoot=\"${SourceRoot}/apps\"" >> /tmp/deploy-apps-${BUILD_NUMBER}.sh
echo "DestinationHost=\"${DestinationHost}\"" >> /tmp/deploy-apps-${BUILD_NUMBER}.sh
echo "DestinationRoot=\"${DestinationRoot}\"" >> /tmp/deploy-apps-${BUILD_NUMBER}.sh
echo "UpdateAppsLink=\"${UpdateAppsLink}\"" >> /tmp/deploy-apps-${BUILD_NUMBER}.sh
cat ~/scripts/deploy-apps-template.sh >> /tmp/deploy-apps-${BUILD_NUMBER}.sh
chmod ug=rwx /tmp/deploy-apps-${BUILD_NUMBER}.sh
sudo chown apps:apps /tmp/deploy-apps-${BUILD_NUMBER}.sh

echo "scp"
sudo -u apps scp /tmp/deploy-apps-${BUILD_NUMBER}.sh apps@${DestinationHost}:~/deploy-apps-${BUILD_NUMBER}.sh

echo "ssh"
sudo -u apps ssh apps@${DestinationHost} "~/deploy-apps-${BUILD_NUMBER}.sh"







# Infrastructure
sudo yum update
sudo amazon-linux-extras enable python3.8
sudo yum clean metadata
sudo yum install -y git python38
sudo ln -s /usr/bin/python3.8 /usr/bin/python3


# Setup MITMProxy
## Note: dev version is commit a42d071995e70e39010d91233d768f25b73a7f95
mkdir ~/sites/
cd ~/sites/
git clone https://github.com/mitmproxy/mitmproxy.git
cd mitmproxy/
git checkout tags/v6.0.0

# Deployment
scp ~/sites/mitm-addon/requirements.txt herodev@54.163.103.92:~/sites/mitmproxy/
ssh herodev@54.163.103.92 "mkdir -p ~/sites/mitmproxy/scintillator/logs"
rsync -ptvz --del --dirs ~/sites/mitm-addon/*.py herodev@54.163.103.92:~/sites/mitmproxy/scintillator/
scp ~/sites/mitm-addon/requirements.txt herodev@54.163.103.92:~/sites/mitmproxy/

#update /etc/environment with RULES_FILE=/home/herodev/sites/mitmproxy/scintillator/rules.json
scp ~/sites/mitm-addon/data/rules.json herodev@54.163.103.92:~/sites/mitmproxy/scintillator/

