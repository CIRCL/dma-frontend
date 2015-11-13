#!/bin/bash

cuckoo_api_url = "http://localhost:8090"
cuckoo_api_tasks_create_file = "/tasks/create/file"
cuckoo_api_tasks_view = "/tasks/view/"

submission_mail = "info@circl.lu"

while true
do
    LISTSIZE=$(redis-cli -n 5 LLEN submit)
    START=0
    echo ${LISTSIZE}
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
        task_id=`curl -F package=${package} -F machine=${machine} -F file=@${file} ${cuckoo_api_url}${cuckoo_api_tasks_create_file} | jq -r .task_id`
        echo "task_id ${task_id}"
        status=$(redis-cli -n 5 SADD t:${user} ${task_id})
        s=`curl ${cuckoo_api_url}${cuckoo_api_tasks_view}${task_id} >/tmp/c-$$`
        fe=`gpg -e -o /tmp/e-$$.gpg -r ${submission_mail} ${file}`
        smail=`mutt -a /tmp/e-$$.gpg -s "New DMA analysis submitted ${task_id} by ${user}" -- ${submission_mail} </tmp/c-$$`
        rm /tmp/e-$$.gpg
    done
    sleep 10
done

