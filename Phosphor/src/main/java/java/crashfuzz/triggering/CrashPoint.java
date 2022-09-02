package java.crashfuzz.triggering;

import java.crashfuzz.instrumenter.TriggerEvent;
import java.crashfuzz.tracing.FAVEntry;

public class CrashPoint implements Comparable<CrashPoint> {
	public TriggerEvent event;
	public FAVEntry CRASH_BEFORE;
	public FAVEntry CRASH_AFTER;
	public FAVEntry DELAY;
    public String CRASH_ID;  //process id + local crash index

    private static CrashPoint emptyIns;
    static {
    	emptyIns = new CrashPoint();
    	emptyIns.event = null;
    	emptyIns.CRASH_BEFORE = null;
    	emptyIns.CRASH_AFTER = null;
    	emptyIns.CRASH_ID = null;
    	emptyIns.DELAY = null;
    }

    public boolean isEmpty() {
    	return CRASH_BEFORE == null && CRASH_ID == null && event == null;
    }

    public static CrashPoint getEmptyIns() {
    	return emptyIns;
    }

    public String toString() {
    	return "[Crash_ID="+CRASH_ID+", Crash_Event="+event+", Crash_Before="+CRASH_BEFORE.toString()+"]";
    }

	@Override
	public int hashCode() {
		// TODO Auto-generated method stub
		int res = 17;
		res = 31 * res + (event == null? 0:event.hashCode());
		res = 31 * res + (CRASH_BEFORE == null? 0:CRASH_BEFORE.hashCode());
		res = 31 * res + (CRASH_AFTER == null? 0:CRASH_AFTER.hashCode());
		res = 31 * res + (DELAY == null? 0:DELAY.hashCode());
		res = 31 * res + (CRASH_ID == null? 0:CRASH_ID.hashCode());
		return res;
	}

	@Override
	public boolean equals(Object obj) {
		// TODO Auto-generated method stub
		if(obj instanceof CrashPoint) {
			CrashPoint p = (CrashPoint) obj;
			if(p.DELAY == null && this.DELAY == null) {
				return this.event.equals(p.event) && this.CRASH_BEFORE.equals(p.CRASH_BEFORE)
						&& this.CRASH_AFTER.equals(p.CRASH_AFTER);
			} else if ((p.DELAY == null && this.DELAY != null) || (p.DELAY != null && this.DELAY == null)) {
				return false;
			} else {
				return this.event.equals(p.event) && this.CRASH_BEFORE.equals(p.CRASH_BEFORE)
						&& this.CRASH_AFTER.equals(p.CRASH_AFTER) && this.DELAY.equals(p.DELAY);
			}
		} else {
			return false;
		}
	}

	@Override
    public int compareTo(CrashPoint o) {
        return this.CRASH_ID.compareTo(o.CRASH_ID);
    }
}
