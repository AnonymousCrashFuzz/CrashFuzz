package java.crashfuzz;

import java.crashfuzz.FaultSequence.FaultPos;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class IOPoint {
	public int ioID;
	public int appearIdx;
	
	public long TIMESTAMP;
	public long THREADID;
	public int THREADOBJ;
	public String PATH;
    public List<String> CALLSTACK;
    public String procID;
    public String ip;
    public int newCovs = 0;
    public FaultPos pos;//before or after
	public String toString() {
		return "IOID=["+ioID+"]"+", IOIP=["+ip+"], AppearIdx=["+appearIdx+"]"+", CallStack="+CALLSTACK
				+", Path="+PATH;
	}
	public int computeIoID() {
		return CALLSTACK.toString().hashCode();
	}
}
