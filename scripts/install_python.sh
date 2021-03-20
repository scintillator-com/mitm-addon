#!/bin/bash

# Infrastructure
sudo yum update -y
sudo amazon-linux-extras enable python3.8
sudo yum clean metadata
sudo yum install -y git python38

if [ ! -L /usr/bin/python3 ]; then
  sudo ln -s /usr/bin/python3.8 /usr/bin/python3
fi

# Setup MITMProxy
if [ ! -d ~/sites/ ]; then
  mkdir ~/sites/
fi

cd ~/sites/
if [ ! -d ~/sites/mitmproxy/ ]; then
  git clone https://github.com/mitmproxy/mitmproxy.git
fi

cd mitmproxy/

#TODO: force
## Note: dev version is commit a42d071995e70e39010d91233d768f25b73a7f95
git checkout tags/v6.0.0
# disabled in favor of venv pip install
#echo "dnspython==2.0.0" >> requirements.txt
#echo "pymongo==3.11.2" >> requirements.txt

#ref: https://github.com/mitmproxy/mitmproxy/blob/master/CONTRIBUTING.md
./dev.sh

#ln -s ~/sites/mitm-addon ~/sites/mitmproxy/scintillator
#//installed requests-2.25.1
#. venv/bin/activate
#mitmdump --set block_global=false -s scintillator/scintillator.py
