START_TIME=`date +%s`

#Start the ZooKeeper cluster
docker exec -t C1ZK1 /bin/bash -ic 'cd /home/evaluation/zk-3.6.3/ && bin/zkServer.sh start'
docker exec -t C1ZK2 /bin/bash -ic 'cd /home/evaluation/zk-3.6.3/ && bin/zkServer.sh start'
docker exec -t C1ZK3 /bin/bash -ic 'cd /home/evaluation/zk-3.6.3/ && bin/zkServer.sh start'
docker exec -t C1ZK4 /bin/bash -ic 'cd /home/evaluation/zk-3.6.3/ && bin/zkServer.sh start'
docker exec -t C1ZK5 /bin/bash -ic 'cd /home/evaluation/zk-3.6.3/ && bin/zkServer.sh start'

#Run client requests
java -cp zkcases.jar edu.iscas.ZKCases.Client "172.30.0.2:11181,172.30.0.3:11181,172.30.0.4:11181,172.30.0.5:11181,172.30.0.6:11181" /mydir/failTest.sh

END_TIME=`date +%s`
EXECUTING_TIME=`expr $END_TIME - $START_TIME`
echo $EXECUTING_TIME
