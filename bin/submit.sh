#!/bin/bash

CUCKOO_API_URL="http://localhost:8090"
CUCKOO_API_TASKS_CREATE_FILE="/tasks/create/file"
CUCKOO_API_TASKS_VIEW="/tasks/view/"
CUCKOO_STATUS="/cuckoo/status"
CUCKOO_VERSION=`curl -s ${CUCKOO_API_URL}${CUCKOO_STATUS} |jq -r .version`
GPG_ENABLE=false

SUBMISSION_MAIL="steve.clement@circl.lu"

if [ ${CUCKOO_VERSION} != "" ]; then
    echo "You run cuckoo version ${CUCKOO_VERSION}"
else
    echo "Could not get cuckoo version from API, perhaps api.py not running?"
    break
fi

while true
do
    LISTSIZE=$(redis-cli -n 5 LLEN submit)
    START=0
    if [ "${LISTSIZE}" != 0 ]; then
        echo ${LISTSIZE}
    fi
    for (( c=1; c<=$LISTSIZE; c++ ))
    do
        VAL=$(redis-cli -n 5 LPOP submit)
        user=`echo "${VAL}" |  cut -f1 -d:`
        file=`echo "${VAL}" |  cut -f2 -d:`
        machine=`echo "${VAL}" |  cut -f3 -d:`
        package=`echo "${VAL}" |  cut -f4 -d:`
        echo "username ${user}"
        echo "file ${file}"
        echo "machine ${machine}"
        echo "package ${package}"
        # xargs is used to trim any leading spaces
        if [ "$CUCKOO_VERSION" = "2.0-dev" ]; then
            task_id=`curl -F package=${package} -F machine=${machine} -F file=@${file} ${CUCKOO_API_URL}${CUCKOO_API_TASKS_CREATE_FILE} | jq -r .task_id | grep '[0-9]' |xargs`
        fi
        if [ "$CUCKOO_VERSION" = "1.3-Optiv" ]; then
            task_id=`curl -F package=${package} -F machine=${machine} -F file=@${file} ${CUCKOO_API_URL}${CUCKOO_API_TASKS_CREATE_FILE} | jq -r .task_ids | grep '[0-9]' |xargs`
        fi
        echo "task_id ${task_id}"
        status=$(redis-cli -n 5 SADD t:${user} ${task_id})
        s=`curl ${CUCKOO_API_URL}${CUCKOO_API_TASKS_VIEW}${task_id} >/tmp/c-$$`
        if [ "$GPG_ENABLE" = true ]; then
            fe=`gpg -e -o /tmp/e-$$.gpg -r ${SUBMISSION_MAIL} ${file}`
            smail=`mutt -a /tmp/e-$$.gpg -s "New DMA analysis submitted ${task_id} by ${user}" -- ${SUBMISSION_MAIL} </tmp/c-$$`
            rm /tmp/e-$$.gpg
        else
            smail=`mutt -s "New DMA analysis submitted ${task_id} by ${user}" -- ${SUBMISSION_MAIL} < /tmp/c-$$`
        fi
    done
    sleep 10
done
