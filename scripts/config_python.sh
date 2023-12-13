#!/bin/bash
echo "=== Configuration Report ==="
echo "= AUTHORIZE: [${AUTHORIZE}]"
echo "= LOG_LEVEL: [${LOG_LEVEL}]"
echo "= MONGO_DB: [${MONGO_DB}]"
echo "= MONGO_URI: [${MONGO_URI}]"
echo "= RATELIMIT: [${RATELIMIT}]"
echo "= RULES_FILE: [${RULES_FILE}]"
echo "= SKIP_AUTH: [${SKIP_AUTH}]"
echo "= WEBSITE: [${WEBSITE}]"
echo "============================"

function upsert(){
  local key=$1
  local value=$2
  local path=$3

  grep -Fq "export ${key}=" "${path}"
  if [ $? -eq 0 ]; then
    sed -i "s/^export ${key}=.*/export ${key}=${value}/" "${path}"
  else
    echo "export ${key}=${value}" | tee -a "${path}"
  fi
}

sudo upsert AUTHORIZE $AUTHORIZE /etc/environment
sudo upsert LOG_LEVEL $LOG_LEVEL /etc/environment
sudo upsert MONGO_DB $MONGO_DB /etc/environment
sudo upsert MONGO_URI $MONGO_URI /etc/environment
sudo upsert RATELIMIT $RATELIMIT /etc/environment
sudo upsert RULES_FILE $RULES_FILE /etc/environment
sudo upsert SKIP_AUTH $SKIP_AUTH /etc/environment
sudo upsert WEBSITE $WEBSITE /etc/environment
