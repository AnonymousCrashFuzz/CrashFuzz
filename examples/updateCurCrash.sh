docker exec -t C1ZK1 /bin/bash -ic 'rm /home/evaluation/zk-3.6.3/curFaultSeq'
docker cp /mydir/curFaultSeq C1ZK1:/home/evaluation/zk-3.6.3
docker exec -t C1ZK2 /bin/bash -ic 'rm /home/evaluation/zk-3.6.3/curFaultSeq'
docker cp /mydir/curFaultSeq C1ZK2:/home/evaluation/zk-3.6.3
docker exec -t C1ZK3 /bin/bash -ic 'rm /home/evaluation/zk-3.6.3/curFaultSeq'
docker cp /mydir/curFaultSeq C1ZK3:/home/evaluation/zk-3.6.3
docker exec -t C1ZK4 /bin/bash -ic 'rm /home/evaluation/zk-3.6.3/curFaultSeq'
docker cp /mydir/curFaultSeq C1ZK4:/home/evaluation/zk-3.6.3
docker exec -t C1ZK5 /bin/bash -ic 'rm /home/evaluation/zk-3.6.3/curFaultSeq'
docker cp /mydir/curFaultSeq C1ZK5:/home/evaluation/zk-3.6.3
