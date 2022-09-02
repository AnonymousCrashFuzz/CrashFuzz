package java.crashfuzz.instrumenter.hdfs;

import java.io.FileOutputStream;
import java.io.IOException;

import edu.columbia.cs.psl.phosphor.struct.LazyByteArrayObjTags;
import edu.columbia.cs.psl.phosphor.Configuration;
import edu.columbia.cs.psl.phosphor.runtime.Taint;
import java.crashfuzz.taint.FAVTaint;
import java.crashfuzz.tracing.RecordTaint;
import java.crashfuzz.triggering.WaitToExec;

public class HDFSRunMode {
    public static void recordYarnRpcOrTrigger(long timestamp, FileOutputStream out, String path, LazyByteArrayObjTags bytes) {
        if(Configuration.RECORD_PHASE) {
            try {
                RecordTaint.recordTaintsEntry(timestamp, out, path, bytes.val, bytes.taints, 0, bytes.val.length, "");
            } catch (IOException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }
        } else {
            WaitToExec.checkCrashEvent(path, "");
        }
        //System.out.println("!!!!GY recordYarnRpcOrTrigger:"+path+", taint:"+Taint.combineTaintArray(bytes.taints));
    }

    public static LazyByteArrayObjTags getTaintedBytes(LazyByteArrayObjTags bytes, String cname, String mname,
            String desc, String type, String tag, String linkSource) {
        if(Configuration.RECORD_PHASE) {
            for(int i = 0; i < bytes.val.length; i++) {
                Taint t = FAVTaint.newFAVTaint(cname, mname, desc, type, tag, linkSource);
                bytes.setTaint(i, t);
            }
            return bytes;
        } else {
            return bytes;
        }
        //return bytes;
    }
}
