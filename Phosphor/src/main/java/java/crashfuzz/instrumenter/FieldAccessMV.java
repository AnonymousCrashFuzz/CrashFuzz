package java.crashfuzz.instrumenter;

//import java.util.ArrayList;
import java.util.HashSet;
//import java.util.List;
import java.util.Set;

import org.objectweb.asm.Label;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;

import edu.columbia.cs.psl.phosphor.Configuration;
import edu.columbia.cs.psl.phosphor.instrumenter.TaintAdapter;
import edu.columbia.cs.psl.phosphor.instrumenter.analyzer.NeverNullArgAnalyzerAdapter;
import edu.columbia.cs.psl.phosphor.runtime.Taint;
import edu.columbia.cs.psl.phosphor.struct.LazyReferenceArrayObjTags;

public class FieldAccessMV extends TaintAdapter implements Opcodes {
    private final String desc;
    private final Type returnType;
    private final String name;
    private final boolean isStatic;
    private final boolean isPublic;
    private final String owner;
    public static Set<Integer> metaObjectIds = new HashSet<Integer>();
    public static Set<String> metaObjectOwners = new HashSet<String>();
    static {
        metaObjectOwners.add("org/apache/hadoop/mapreduce/v2/app/MRAppMaster");
        metaObjectOwners.add("org/apache/hadoop/yarn/server/nodemanager/NodeManager");
        metaObjectOwners.add("org/apache/hadoop/mapred/YarnChild");
        metaObjectOwners.add("org/apache/hadoop/mapreduce/v2/hs/JobHistoryServer");
        metaObjectOwners.add("org/apache/hadoop/yarn/server/resourcemanager/ResourceManager");
        metaObjectOwners.add("org/apache/hadoop/yarn/server/webproxy/WebAppProxyServer");
    }

    //take znode path as path, znode value as value, record value taint to path
    //specifically record delete operation with taint empty
    //take every return value of every public method as a read
    public FieldAccessMV(MethodVisitor mv, int access, String owner, String name, String descriptor, String signature,
            String[] exceptions, String originalDesc, NeverNullArgAnalyzerAdapter analyzer) {
        super(access, owner, name, descriptor, signature, exceptions, mv, analyzer);
        this.desc = descriptor;
        this.returnType = Type.getReturnType(desc);
        this.isStatic = (access & Opcodes.ACC_STATIC) != 0;
        this.isPublic = (access & Opcodes.ACC_PUBLIC) != 0;
        this.name = name;
        this.owner = owner;
    }

    @Override
    public void visitCode() {
        // TODO Auto-generated method stub
        super.visitCode();
        if(owner.startsWith("org/apache/hadoop") && this.isStatic
                && (this.name.equals("main") && this.desc.equals("([Ljava/lang/String;)V")
                        || this.name.equals("main$$PHOSPHORTAGGED")
                        && this.desc.equals("("+Type.getDescriptor(LazyReferenceArrayObjTags.class)+Configuration.TAINT_TAG_DESC+"[Ljava/lang/String;)V"))) {
            super.visitLdcInsn(this.owner+"."+this.name+this.desc);
            super.visitMethodInsn(INVOKESTATIC, "java/crashfuzz/instrumenter/FieldAccessMV",
                                    "record", "(Ljava/lang/String;)V", false);
        }
        if(owner.endsWith("ApplicationMaster")) {
            super.visitLdcInsn("ApplicationMaster "+this.name);
            super.visitMethodInsn(INVOKESTATIC, "java/crashfuzz/instrumenter/FieldAccessMV",
                                    "record", "(Ljava/lang/String;)V", false);
        }
    }

    public void visitInsn(int opcode) {
        //use lvs would introduce errors, avoid to use lvs
         if(opcode == RETURN
                 && (owner.equals("org/apache/hadoop/mapreduce/v2/app/MRAppMaster")
                 || owner.equals("org/apache/hadoop/yarn/server/nodemanager/NodeManager")
                 || owner.equals("org/apache/hadoop/mapred/YarnChild")
                 || owner.equals("org/apache/hadoop/mapreduce/v2/hs/JobHistoryServer")
                 || owner.equals("org/apache/hadoop/yarn/server/resourcemanager/ResourceManager")
                 || owner.equals("org/apache/hadoop/yarn/server/webproxy/WebAppProxyServer"))
                 && name.equals("<init>")) {
             super.visitVarInsn(ALOAD, 0);
             super.visitMethodInsn(INVOKEVIRTUAL, "java/lang/Object", "hashCode", "()I", false);
             super.visitMethodInsn(INVOKESTATIC, "java/crashfuzz/instrumenter/FieldAccessMV",
                     "addInitMeta", "(I)V", false);
         }
         super.visitInsn(opcode);
    }

    public static void addInitMeta(int o) {
//        metaObjectIds.add(o);
    }
    @Override
    public void visitMethodInsn(int opcode, String owner, String name, String descriptor, boolean isInterface) {
        // TODO Auto-generated method stub
        super.visitMethodInsn(opcode, owner, name, descriptor, isInterface);
    }

    public static void isMetaObject(Object o, Taint t, String s) {
//        int i = -1;
//        try {
//            i = o.hashCode();
//        } catch (Exception e) {
//            return;
//        }
//        if(metaObjectIds.contains(i)) {
//            System.out.println("!!!GY put meta taint: "+s+", "+o.getClass()+", "+t);
//            record(t, s);
//        }
    }

    public static void addNewMeta(Object o, Object newO, String newDesc) {
//        int i = -1;
//        int j = -1;
//        try {
//            i = o.hashCode();
//            j = newO.hashCode();
//        } catch (Exception e) {
//            return;
//        }
//        if(metaObjectIds.contains(i)) {
//            String inter = Type.getType(newDesc).getInternalName();
//            if(inter.startsWith("org/appache/hadoop")) {
//                System.out.println("!!!GY add new meta: "+newDesc);
//                metaObjectIds.add(j);
//                metaObjectOwners.add(inter);
//            }
//        }
    }

    @Override
    public void visitFieldInsn(int opcode, String owner, String name, String descriptor) {
        // TODO Auto-generated method stub
//        if(opcode == Opcodes.PUTFIELD || opcode == Opcodes.PUTSTATIC) {
//            if(Configuration.USE_FAV && owner.startsWith("org/apache/hadoop")
//                    && !owner.startsWith("org/apache/hadoop/yarn/proto/")
//                    && descriptor.equals(Configuration.TAINT_TAG_DESC)) {
//                super.visitInsn(DUP);
//                super.visitLdcInsn(this.owner+"."+this.name+" put "+owner+"."+name);
//                super.visitMethodInsn(INVOKESTATIC, "java/crashfuzz/instrumenter/FieldAccessMV",
//                                        "record", "("+Configuration.TAINT_TAG_DESC+"Ljava/lang/String;)V", false);
//            }
//        }
        if(opcode == Opcodes.PUTFIELD) {
            if(descriptor.equals(Configuration.TAINT_TAG_DESC)
                    && owner.startsWith("org/apache/hadoop")
                    && !this.name.startsWith("hashCode")
                    && metaObjectOwners.contains(owner)) {
                super.visitInsn(DUP2);
                int taint = lvs.getTmpLV();
                super.visitVarInsn(ASTORE, taint);
                int obj = lvs.getTmpLV();
                super.visitVarInsn(ASTORE, obj);
                org.objectweb.asm.tree.FrameNode fn = getCurrentFrameNode();
                super.visitVarInsn(ALOAD, obj);
                Label nll = new Label();
                super.visitJumpInsn(Opcodes.IFNULL, nll);
                super.visitVarInsn(ALOAD, obj);
                org.objectweb.asm.tree.FrameNode objFn = getCurrentFrameNode();
                if(objFn.stack.get(objFn.stack.size()-1) != Opcodes.UNINITIALIZED_THIS) {
                    super.visitVarInsn(ALOAD, taint);
                    super.visitLdcInsn(this.owner+"."+this.name+" put "+owner+"."+name);
                    super.visitMethodInsn(INVOKESTATIC, "java/crashfuzz/instrumenter/FieldAccessMV",
                          "isMetaObject", "(Ljava/lang/Object;"+Configuration.TAINT_TAG_DESC+"Ljava/lang/String;)V", false);
                } else {
                    super.visitInsn(POP);
                }
                super.visitLabel(nll);
                acceptFn(fn);
                lvs.freeTmpLV(taint);
                lvs.freeTmpLV(obj);
            }
            if(opcode == Opcodes.PUTFIELD) {
                if(!descriptor.equals(Configuration.TAINT_TAG_DESC)
                        && owner.startsWith("org/apache/hadoop")
                        && !this.name.startsWith("hashCode")
                        && metaObjectOwners.contains(owner)) {
                    int field = -1;
                    int obj = -1;
                    org.objectweb.asm.tree.FrameNode fn0 = getCurrentFrameNode();
                    int loadCode = -1;
                    int storeCode = -1;
                    if(fn0.stack.get(fn0.stack.size()-1) == Opcodes.INTEGER) {
                        field = lvs.getTmpLV();
                        super.visitVarInsn(ISTORE, field);
                        obj = lvs.getTmpLV();
                        super.visitVarInsn(ASTORE, obj);
                        super.visitVarInsn(ALOAD, obj);
                        super.visitVarInsn(ILOAD, field);
                        loadCode = ILOAD;
                        storeCode = ISTORE;
                    } else if(fn0.stack.get(fn0.stack.size()-1) == Opcodes.LONG) {
                        field = lvs.getTmpLV();
                        super.visitVarInsn(Opcodes.LSTORE, field);
                        obj = lvs.getTmpLV();
                        super.visitVarInsn(ASTORE, obj);
                        super.visitVarInsn(ALOAD, obj);
                        super.visitVarInsn(LLOAD, field);
                        loadCode = LLOAD;
                        storeCode = LSTORE;
                    } else if(fn0.stack.get(fn0.stack.size()-1) == Opcodes.FLOAT) {
                        field = lvs.getTmpLV();
                        super.visitVarInsn(Opcodes.FSTORE, field);
                        obj = lvs.getTmpLV();
                        super.visitVarInsn(ASTORE, obj);
                        super.visitVarInsn(ALOAD, obj);
                        super.visitVarInsn(FLOAD, field);
                        loadCode = FLOAD;
                        storeCode = FSTORE;
                    } else if(fn0.stack.get(fn0.stack.size()-1) == Opcodes.DOUBLE) {
                        field = lvs.getTmpLV();
                        super.visitVarInsn(Opcodes.DSTORE, field);
                        obj = lvs.getTmpLV();
                        super.visitVarInsn(ASTORE, obj);
                        super.visitVarInsn(ALOAD, obj);
                        super.visitVarInsn(DLOAD, field);
                        loadCode = DLOAD;
                        storeCode = DSTORE;
                    } else if(fn0.stack.get(fn0.stack.size()-1) == Opcodes.NULL
                            || fn0.stack.get(fn0.stack.size()-1) instanceof String) {
                        field = lvs.getTmpLV();
                        super.visitVarInsn(Opcodes.ASTORE, field);
                        obj = lvs.getTmpLV();
                        super.visitVarInsn(ASTORE, obj);
                        super.visitVarInsn(ALOAD, obj);
                        super.visitVarInsn(ALOAD, field);
                        loadCode = ALOAD;
                        storeCode = ASTORE;
                    }

                    org.objectweb.asm.tree.FrameNode fn = getCurrentFrameNode();
                    super.visitVarInsn(ALOAD, obj);
                    Label nll = new Label();
                    super.visitJumpInsn(Opcodes.IFNULL, nll);
                    super.visitVarInsn(ALOAD, obj);
                    super.visitVarInsn(loadCode, field);
                    org.objectweb.asm.tree.FrameNode objFn = getCurrentFrameNode();
                    int stackSize = objFn.stack.size();
                    if(objFn.stack.get(stackSize-2) != Opcodes.UNINITIALIZED_THIS
                            && objFn.stack.get(stackSize-1) instanceof java.lang.String) {
                        super.visitLdcInsn(descriptor);
                        super.visitMethodInsn(INVOKESTATIC, "java/crashfuzz/instrumenter/FieldAccessMV",
                              "addNewMeta", "(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/String;)V", false);
                    } else {
                        super.visitVarInsn(storeCode, field);
                        super.visitInsn(POP);
                    }
                    super.visitLabel(nll);
                    acceptFn(fn);
                    lvs.freeTmpLV(field);
                    lvs.freeTmpLV(obj);
                }
            }
//            if(Configuration.USE_FAV && !descriptor.equals(Configuration.TAINT_TAG_DESC)) {
//                super.visitInsn(DUP2);
//                super.visitInsn(SWAP);
//                super.visitMethodInsn(INVOKEVIRTUAL, owner, "hashcode", "()I", false);
//                super.visitInsn(SWAP);
//                super.visitMethodInsn(INVOKEVIRTUAL, Type.getType(descriptor).getInternalName(), "hashcode", "()I", false);
//                super.visitMethodInsn(INVOKESTATIC, "java/crashfuzz/instrumenter/FieldAccessMV",
//                        "addNewMeta", "(II)V", false);
//            }
        }
        super.visitFieldInsn(opcode, owner, name, descriptor);
    }

    public static void record(Taint t, String f) {
//        StackTraceElement[] callStack;
//        callStack = Thread.currentThread().getStackTrace();
//        List<String> callStackString = new ArrayList<String>();
//        for(int i = 3; i < callStack.length; ++i) {
//            callStackString.add(callStack[i].toString());
//        }
//        if(t != null && !t.isEmpty() && t.toString().contains("FAVMSG")) {
//            System.out.println("!!!!!GY record field "+f+", "+t+", "+callStackString);
//        }
    }

    public static void record(String f) {
//        StackTraceElement[] callStack;
//        callStack = Thread.currentThread().getStackTrace();
//        List<String> callStackString = new ArrayList<String>();
//        for(int i = 3; i < callStack.length; ++i) {
//            callStackString.add(callStack[i].toString());
//        }
//        System.out.println("!!!!!GY record main "+f+", "+callStackString);
    }
}
