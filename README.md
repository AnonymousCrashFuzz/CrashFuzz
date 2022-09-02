# Coverage Guided Fault Injection for Cloud Systems

CrashFuzz is a tool for injecting node crashes/reboots according to system runtime feedbacks when testing cloud systems.

Modern cloud systems are designed to tolerate partial node crashes. However, the combinations of node crashes and reboots that happen at specific time can trigger crash recovery bugs that lie in incorrect crash recovery code.

To ensure a cloud system is resilient to partial node crashes, CrashFuzz smartly explores the fault scenarios to test the target system. To be specific, CrashFuzz takes fault sequences, i.e., possible node crashes and reboots that happen on different I/O points, as the special system inputs. Inspired by fuzzing testing, CrashFuzz generates and mutates fault sequences based on the system runtime feedbacks including code coverage information and I/O information. Also, CrashFuzz prioritizes fault sequences to be tested based on the execution feedbacks and heuristic strategies.
	
## Bugs Detected by CrashFuzz

We applied CrashFuzz to three widely-used cloud systems including ZooKeeper v3.6.3, HDFS v3.3.1 and HBase v2.4.6. The following table shows the bugs detected by CrashFuzz in these systems for now.

| Bug ID | Failure Symptom |
| ---------- | :-----------:  |
| [HBASE-26883](https://issues.apache.org/jira/browse/HBASE-26883) | Data loss |
| [ZOOKEEPER-4503](https://issues.apache.org/jira/browse/ZOOKEEPER-4503) | Data staleness |
| [HBASE-26897](https://issues.apache.org/jira/browse/HBASE-26897) | Cluster out of service |
| [HBASE-26370](https://issues.apache.org/jira/browse/HBASE-26370) | Misleading error message |
| [HDFS-16508](https://issues.apache.org/jira/browse/HDFS-16508) | Operation failure |

## Getting Started

We implement our CrashFuzz code based on Phosphor(https://github.com/gmu-swe/phosphor).

### Prepare an instrumented JRE

Similar to Phosphor, you need to first prepare a instrumented JRE by running the following command:

```
java -jar CrashFuzz.jar -forJava <jre_path> <output_path>
```

### Configure every node in the cluster to use CrashFuzz

Configure every node in the cluster to use the instrumented JRE and include CrashFuzz as the Java agent with a JVM argument. We take ZooKeeper as an example:

```
export JVM_OPTS="$JVM_OPTS -Xbootclasspath/a:<crashfuzz_path>/CrashFuzz.jar -javaagent:<crashfuzz_path>/CrashFuzz.jar=jdkFile=true,recordPath=<io_records_path>,hdfsApi=false,zkApi=false,forHdfs=false,forHbase=false,forZk=true,currentCrash=<current_fault_sequence_file>,controllerSocket=<fault_injection_controller_ip>:<fault_injection_controller_port>,covPath=<code_coverage_dir>,aflPort=<port_for_receiving_commands>"
```

The parameters are explained as follows:
- jdkFile: "true" for tracing local file read/write operations'
- recordPath: specify the path to store I/O information;
- hdfsApi: "true" for tracing read/write operations to HDFS system at the Application level;
- zkApi: "true" for tracing read/write operations to ZooKeeper system at the Application level;
- forHdfs: "true" for testing HDFS system at the Application level;
- forHbase: "true" for testing HBase system at the Application level;
- forZk: "true" for testing ZooKeeper system at the Application level;
- currentCrash: specify the file to store current fault sequence under test;
- controllerSocket: specify the socket information of the fault injection controller;
- covPath: specify the path to store coverage information;
- aflPort: specify the port used for receiving commands from the fault injection controller

### Run CrashFuzz

Run the following command to start CrashFuzz and perform crash/reboot injection testing:

```
java -cp CrashFuzz.jar java.crashfuzz.CloudFuzzMain <fault_injection_controller_port> "conf.properties"
```

The `conf.properties` file specifies related configurations and scripts used by CrashFuzz. An example of `conf.properties` is shown as following:

```
#Specify the workload used by CrashFuzz. The workload should contains the startup process of the target system
WORKLOAD=/mydir/workload.sh
#Specify the script for initializing the enviroment before running the workload
PRETREATMENT=/mydir/prepareEnv.sh
#Specify the script for killing a node according to the node IP
CRASH=/mydir/crashNode.sh
#Specify the script for starting a node according to the node IP
RESTART=/mydir/startNode.sh
#Specify the predefined bug checker
CHECKER=/mydir/workloadChecker.sh
#Specify the root directory for the testing results
ROOT_DIR=/mydir/crash-fuzz-report
#Specify the file that stores the current fault sequence under test
CUR_CRASH_FILE=/mydir/curFaultSeq
#Specify the script for copying the current fault sequence file to every node in the target cluster.
UPDATE_CRASH=/mydir/updateCurCrash.sh
#Specify the script for collecting runtime feedbacks from every node
MONITOR=/mydir/monitor.sh
#Specify the maximum number of downtime nodes that the target system can tolerate. In this example, the target system can tolerate downtime of up to two nodes in ip1, ip2 and ip3, and can tolerate downtime of up to one node in ip4 and ip5.
FAULT_CSTR=2:{ip1,ip2,ip3};1:{ip4,ip5}
#Specify the maxium test time
TEST_TIME=10h
#Specify the timeout time used for confirming hang bugs
HANG_TMOUT=10m
#Specify the maximum number of node crashes and reboots occur in a fault sequence
MAX_FAULTS=10
#Specify the port used by every node for receiving commands from the fault injection controller
AFL_PORT=12181
```
