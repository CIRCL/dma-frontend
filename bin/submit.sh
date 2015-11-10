#!/bin/bash
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
                task_id=`curl -F package=${package} -F machine=${machine} -F file=@${file} http://crg.circl.lu:8090/tasks/create/file | jq -r .task_id`
                echo "task_id ${task_id}"
                status=$(redis-cli -n 5 SADD t:${user} ${task_id})
                s=`curl http://crg.circl.lu:8090/tasks/view/${task_id} >/tmp/c-$$`
                fe=`gpg -e -o /tmp/e-$$.gpg -r info@circl.lu ${file}`
                smail=`mutt -a /tmp/e-$$.gpg -s "New DMA analysis submitted ${task_id} by ${user}" -- info@circl.lu </tmp/c-$$`
                rm /tmp/e-$$.gpg
        done
        sleep 10
done

