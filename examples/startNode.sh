function start {
        nodeName=""
        daemonName=""
        case $1 in
           172.30.0.2)
              nodeName="C1ZK1"
              daemonName=""
              ;;
           172.30.0.3)
              nodeName="C1ZK2"
              daemonName=""
              ;;
           172.30.0.4)
              nodeName="C1ZK3"
              daemonName=""
              ;;
           172.30.0.5)
              nodeName="C1ZK4"
              daemonName=""
              ;;
           172.30.0.6)
              nodeName="C1ZK5"
              daemonName=""
              ;;
        esac

        docker start $nodeName
        docker exec -t $nodeName /bin/bash -ic 'cd /home/evaluation/zk-3.6.3/ && bin/zkServer.sh start'
}

start $1
