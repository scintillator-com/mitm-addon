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
    sudo sed -i "s/^export ${key}=.*/export ${key}=${value}/" "${path}"
  else
    echo "export ${key}=${value}" | sudo tee -a "${path}"
  fi
}

upsert AUTHORIZE $AUTHORIZE /etc/environment
upsert LOG_LEVEL $LOG_LEVEL /etc/environment
upsert MONGO_DB $MONGO_DB /etc/environment
upsert MONGO_URI $MONGO_URI /etc/environment
upsert RATELIMIT $RATELIMIT /etc/environment
upsert RULES_FILE $RULES_FILE /etc/environment
upsert SKIP_AUTH $SKIP_AUTH /etc/environment
upsert WEBSITE $WEBSITE /etc/environment
