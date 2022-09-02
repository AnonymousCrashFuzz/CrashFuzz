mkdir $1/monitor

mkdir $1/monitor/C1ZK1
docker cp C1ZK1:/home/evaluation/zk-3.6.3/logs $1/monitor/C1ZK1
docker cp C1ZK1:/home/evaluation/zk-3.6.3/zkData $1/monitor/C1ZK1

mkdir $1/monitor/C1ZK2
docker cp C1ZK2:/home/evaluation/zk-3.6.3/logs $1/monitor/C1ZK2
docker cp C1ZK2:/home/evaluation/zk-3.6.3/zkData $1/monitor/C1ZK2

mkdir $1/monitor/C1ZK3
docker cp C1ZK3:/home/evaluation/zk-3.6.3/logs $1/monitor/C1ZK3
docker cp C1ZK3:/home/evaluation/zk-3.6.3/zkData  $1/monitor/C1ZK3

mkdir $1/monitor/C1ZK4
docker cp C1ZK4:/home/evaluation/zk-3.6.3/logs $1/monitor/C1ZK4
docker cp C1ZK4:/home/evaluation/zk-3.6.3/zkData  $1/monitor/C1ZK4

mkdir $1/monitor/C1ZK5
docker cp C1ZK5:/home/evaluation/zk-3.6.3/logs $1/monitor/C1ZK5
docker cp C1ZK5:/home/evaluation/zk-3.6.3/zkData  $1/monitor/C1ZK5

mkdir $1/fav-rst
docker cp C1ZK1:/home/evaluation/zk-3.6.3/io_info $1/fav-rst/
mv $1/fav-rst/io_info/* $1/fav-rst/
rm -r $1/fav-rst/io_info
docker cp C1ZK2:/home/evaluation/zk-3.6.3/io_info $1/fav-rst/
mv $1/fav-rst/io_info/* $1/fav-rst/
rm -r $1/fav-rst/io_info
docker cp C1ZK3:/home/evaluation/zk-3.6.3/io_info $1/fav-rst/
mv $1/fav-rst/io_info/* $1/fav-rst/
rm -r $1/fav-rst/io_info
docker cp C1ZK4:/home/evaluation/zk-3.6.3/io_info $1/fav-rst/
mv $1/fav-rst/io_info/* $1/fav-rst/
rm -r $1/fav-rst/io_info
docker cp C1ZK5:/home/evaluation/zk-3.6.3/io_info $1/fav-rst/
mv $1/fav-rst/io_info/* $1/fav-rst/
rm -r $1/fav-rst/io_info

mkdir $1/cov
mkdir $1/cov/C1ZK1
docker cp C1ZK1:/home/evaluation/zk-3.6.3/coverage_info $1/cov/C1ZK1

mkdir $1/cov/C1ZK2
docker cp C1ZK2:/home/evaluation/zk-3.6.3/coverage_info $1/cov/C1ZK2

mkdir $1/cov/C1ZK3
docker cp C1ZK3:/home/evaluation/zk-3.6.3/coverage_info $1/cov/C1ZK3

mkdir $1/cov/C1ZK4
docker cp C1ZK4:/home/evaluation/zk-3.6.3/coverage_info $1/cov/C1ZK4

mkdir $1/cov/C1ZK5
docker cp C1ZK5:/home/evaluation/zk-3.6.3/coverage_info $1/cov/C1ZK5
