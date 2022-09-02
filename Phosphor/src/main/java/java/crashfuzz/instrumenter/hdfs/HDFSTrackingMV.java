package java.crashfuzz.instrumenter.hdfs;

import edu.columbia.cs.psl.phosphor.Configuration;
import edu.columbia.cs.psl.phosphor.TaintUtils;

import org.objectweb.asm.tree.FrameNode;
import edu.columbia.cs.psl.phosphor.instrumenter.TaintAdapter;
import edu.columbia.cs.psl.phosphor.instrumenter.analyzer.NeverNullArgAnalyzerAdapter;
import edu.columbia.cs.psl.phosphor.struct.LazyByteArrayObjTags;
import edu.columbia.cs.psl.phosphor.struct.TaintedReferenceWithObjTag;
import java.crashfuzz.taint.FAVTaintType;
import java.crashfuzz.taint.Source.FAVTagType;
import java.crashfuzz.tracing.FAVPathType;

import org.objectweb.asm.*;
import static edu.columbia.cs.psl.phosphor.instrumenter.TaintMethodRecord.*;

import java.net.InetSocketAddress;

public class HDFSTrackingMV extends TaintAdapter implements Opcodes {
    private final String desc;
    private final Type returnType;
    private final String name;
    private final boolean isStatic;
    private final boolean isPublic;
    private final String owner;
    private final String ownerSuperCname;
    private final String[] ownerInterfaces;

    public HDFSTrackingMV(MethodVisitor mv, int access, String owner, String name, String descriptor, String signature,
            String[] exceptions, String originalDesc, NeverNullArgAnalyzerAdapter analyzer,
            String superCname, String[] interfaces) {
        super(access, owner, name, descriptor, signature, exceptions, mv, analyzer);
        this.desc = descriptor;
        this.returnType = Type.getReturnType(desc);
        this.isStatic = (access & Opcodes.ACC_STATIC) != 0;
        this.isPublic = (access & Opcodes.ACC_PUBLIC) != 0;
        this.name = name;
        this.owner = owner;
        this.ownerSuperCname = superCname;
        this.ownerInterfaces = interfaces;
    }

    private int remoteIpVar = -1;
    public void visitCode() {
        if(Configuration.USE_FAV && Configuration.FOR_HDFS) {
            if(HDFSProtocols.isServerSideRpcCall(this.owner, this.name, this.desc,
                    this.ownerSuperCname, this.ownerInterfaces)) {
                //generate new taints for server side rpc call
//                System.out.println("!!!!!!!!!GY Server"+this.owner+"."+this.name);
                String requestType = HDFSProtocols.getRequestProtoInternalTypeFromDesc(this.desc);
                attachTaintTagsToMessage(4, requestType, this.owner, this.name, this.desc, FAVTaintType.RPC.toString(), FAVTagType.APP.toString(), true);
            }
        }
        super.visitCode();
    }

    public void attachTaintTagsToMessage(int msgVar, String msgInternalType, String cname, String mname,
            String desc, String type, String tag, boolean recordRemoteIP) {
    	FAV_GET_RECORD_OUT.delegateVisit(mv);
        int fileOutStream = lvs.getTmpLV();
        super.visitVarInsn(Opcodes.ASTORE, fileOutStream);

        Label nullOutStream = new Label();
        FrameNode outFn = getCurrentFrameNode();
        super.visitVarInsn(Opcodes.ALOAD, fileOutStream);
        super.visitJumpInsn(Opcodes.IFNULL, nullOutStream);

        super.visitVarInsn(Opcodes.ALOAD, fileOutStream);
        super.visitLdcInsn(0);  //set FAV_RECORD_TAG to false, avoid dead loop
        super.visitFieldInsn(Opcodes.PUTFIELD, "java/io/FileOutputStream", TaintUtils.FAV_RECORD_TAG, "Z");

        super.visitLabel(nullOutStream);
        acceptFn(outFn);

        FAV_GET_TIMESTAMP.delegateVisit(mv);
        super.visitVarInsn(Opcodes.ALOAD, fileOutStream);

        if(Configuration.IS_THIRD_PARTY_PROTO) {
        	super.visitVarInsn(ALOAD, msgVar);
            super.visitMethodInsn(INVOKEVIRTUAL, msgInternalType,
                    "getUnknownFields", "()Lorg/apache/hadoop/thirdparty/protobuf/UnknownFieldSet;", false);
            super.visitIntInsn(Opcodes.SIPUSH, Configuration.PROTO_MSG_ID_TAG);
            super.visitMethodInsn(INVOKEVIRTUAL, "org/apache/hadoop/thirdparty/protobuf/UnknownFieldSet",
                    "getField", "(I)Lorg/apache/hadoop/thirdparty/protobuf/UnknownFieldSet$Field;", false);
            super.visitMethodInsn(INVOKEVIRTUAL, "org/apache/hadoop/thirdparty/protobuf/UnknownFieldSet$Field",
                    "getLengthDelimitedList", "()Ljava/util/List;", false);
            super.visitMethodInsn(INVOKESTATIC, "java/crashfuzz/instrumenter/yarn/YarnInstrument",
                    "getLinkSourceFromMsg", "(Ljava/util/List;)Ljava/lang/Object;", false);
            int rawsource = lvs.getTmpLV();
            super.visitVarInsn(ASTORE, rawsource);
            super.visitLdcInsn(FAVPathType.FAVMSG.toString()+":");
            int stringsource = lvs.getTmpLV();
            super.visitVarInsn(ASTORE, stringsource);
            Label done = new Label();
            FrameNode fn = getCurrentFrameNode();
            super.visitVarInsn(ALOAD, rawsource);
            super.visitTypeInsn(INSTANCEOF, "org/apache/hadoop/thirdparty/protobuf/ByteString");
            super.visitJumpInsn(Opcodes.IFEQ, done);
            super.visitVarInsn(ALOAD, rawsource);
            super.visitTypeInsn(CHECKCAST, "org/apache/hadoop/thirdparty/protobuf/ByteString");
            super.visitMethodInsn(INVOKEVIRTUAL, "org/apache/hadoop/thirdparty/protobuf/ByteString",
                    "toStringUtf8", "()Ljava/lang/String;", false);
            super.visitVarInsn(ASTORE, stringsource);
            super.visitLabel(done);
            acceptFn(fn);
            if(recordRemoteIP) {
                super.visitVarInsn(ALOAD, stringsource);
                super.visitMethodInsn(INVOKESTATIC, "java/crashfuzz/instrumenter/yarn/YarnInstrument",
                        "getRemoteAddrFromSource", "(Ljava/lang/String;)Ljava/lang/String;", false);
                remoteIpVar = lvs.createPermanentLocalVariable(String.class, "FAV_REMOTE_IP");
                super.visitVarInsn(ASTORE, remoteIpVar);
            }
            super.visitVarInsn(ALOAD, stringsource);
            super.visitMethodInsn(INVOKESTATIC, "java/crashfuzz/instrumenter/yarn/YarnInstrument",
                    "appendRead", "(Ljava/lang/String;)Ljava/lang/String;", false);
            lvs.freeTmpLV(stringsource);
            lvs.freeTmpLV(rawsource);
        } else {
        	super.visitVarInsn(ALOAD, msgVar);
            super.visitMethodInsn(INVOKEVIRTUAL, msgInternalType,
                    "getUnknownFields", "()Lcom/google/protobuf/UnknownFieldSet;", false);
            super.visitIntInsn(Opcodes.SIPUSH, Configuration.PROTO_MSG_ID_TAG);
            super.visitMethodInsn(INVOKEVIRTUAL, "com/google/protobuf/UnknownFieldSet",
                    "getField", "(I)Lcom/google/protobuf/UnknownFieldSet$Field;", false);
            super.visitMethodInsn(INVOKEVIRTUAL, "com/google/protobuf/UnknownFieldSet$Field",
                    "getLengthDelimitedList", "()Ljava/util/List;", false);
            super.visitMethodInsn(INVOKESTATIC, "java/crashfuzz/instrumenter/yarn/YarnInstrument",
                    "getLinkSourceFromMsg", "(Ljava/util/List;)Ljava/lang/Object;", false);
            int rawsource = lvs.getTmpLV();
            super.visitVarInsn(ASTORE, rawsource);
            super.visitLdcInsn(FAVPathType.FAVMSG.toString()+":");
            int stringsource = lvs.getTmpLV();
            super.visitVarInsn(ASTORE, stringsource);
            Label done = new Label();
            FrameNode fn = getCurrentFrameNode();
            super.visitVarInsn(ALOAD, rawsource);
            super.visitTypeInsn(INSTANCEOF, "com/google/protobuf/ByteString");
            super.visitJumpInsn(Opcodes.IFEQ, done);
            super.visitVarInsn(ALOAD, rawsource);
            super.visitTypeInsn(CHECKCAST, "com/google/protobuf/ByteString");
            super.visitMethodInsn(INVOKEVIRTUAL, "com/google/protobuf/ByteString",
                    "toStringUtf8", "()Ljava/lang/String;", false);
            super.visitVarInsn(ASTORE, stringsource);
            super.visitLabel(done);
            acceptFn(fn);
            if(recordRemoteIP) {
                super.visitVarInsn(ALOAD, stringsource);
                super.visitMethodInsn(INVOKESTATIC, "java/crashfuzz/instrumenter/yarn/YarnInstrument",
                        "getRemoteAddrFromSource", "(Ljava/lang/String;)Ljava/lang/String;", false);
                remoteIpVar = lvs.createPermanentLocalVariable(String.class, "FAV_REMOTE_IP");
                super.visitVarInsn(ASTORE, remoteIpVar);
            }
            super.visitVarInsn(ALOAD, stringsource);
            super.visitMethodInsn(INVOKESTATIC, "java/crashfuzz/instrumenter/yarn/YarnInstrument",
                    "appendRead", "(Ljava/lang/String;)Ljava/lang/String;", false);
            lvs.freeTmpLV(stringsource);
            lvs.freeTmpLV(rawsource);
        }
        APP_FAULT_BEFORE.delegateVisit(mv);
        //[rtn]

        lvs.freeTmpLV(fileOutStream);
    }

    public static void checkSocket(String addr) {
        System.out.println("!!!!GY client side addr is "+addr);
    }
    public void checkAndStoreRpcSocket(String desc) {
        Type[] args = Type.getArgumentTypes(desc);
        int[] vars = new int[args.length];
        int classVar = -1;
        int socketVar = -1;

        for(int i = args.length - 1; i >= 0; i--) {
            vars[i] = lvs.getTmpLV();
            if(args[i].getSort() == Type.OBJECT || args[i].getSort() == Type.ARRAY) {
                super.visitVarInsn(ASTORE, vars[i]);
                if(args[i].getInternalName().equals("java/lang/Class")) {
                    classVar = vars[i];
                } else if (args[i].getInternalName().equals("java/net/InetSocketAddress")) {
                    socketVar = vars[i];
                }
            } else if(args[i].getSort() == Type.DOUBLE) {
                super.visitVarInsn(Opcodes.DSTORE, vars[i]);
            } else if(args[i].getSort() == Type.LONG) {
                super.visitVarInsn(Opcodes.LSTORE, vars[i]);
            } else if(args[i].getSort() == Type.FLOAT) {
                super.visitVarInsn(Opcodes.FSTORE, vars[i]);
            } else if(args[i].getSort() == Type.INT || args[i].getSort() == Type.SHORT
                    || args[i].getSort() == Type.BYTE || args[i].getSort() == Type.CHAR
                    || args[i].getSort() == Type.BOOLEAN) {
                super.visitVarInsn(ISTORE, vars[i]);
            } else {
                //this would not happen
            }
        }

        super.visitVarInsn(ALOAD, classVar);
        super.visitVarInsn(ALOAD, socketVar);
        super.visitMethodInsn(INVOKESTATIC, "java/crashfuzz/instrumenter/yarn/YarnInstrument",
                "storeHDFSRpcClientSideSocket",
                "(Ljava/lang/Class;"+Type.getDescriptor(InetSocketAddress.class)+")Ljava/lang/String;", false);
        int addrstr = lvs.getTmpLV();
        super.visitVarInsn(ASTORE, addrstr);

        Label done = new Label();
        FrameNode fn = getCurrentFrameNode();
        super.visitVarInsn(ALOAD, addrstr);
        super.visitJumpInsn(Opcodes.IFNULL, done);
        super.visitVarInsn(ALOAD, 0);
        super.visitVarInsn(ALOAD, addrstr);
        super.visitFieldInsn(PUTFIELD, this.owner, TaintUtils.FAV_RPC_SOCKET, "Ljava/lang/String;");
//        super.visitVarInsn(ALOAD, 0);
//        super.visitFieldInsn(GETFIELD, this.owner, TaintUtils.FAV_YARN_RPC_SOCKET, "Ljava/lang/String;");
//        super.visitMethodInsn(INVOKESTATIC, "java/crashfuzz/instrumenter/hdfs/HDFSTackingMV",
//                "checkSocket", "(Ljava/lang/String;)V", false);
        super.visitLabel(done);
        acceptFn(fn);

        for(int i = 0; i < args.length; i++) {
            if(args[i].getSort() == Type.OBJECT || args[i].getSort() == Type.ARRAY) {
                super.visitVarInsn(ALOAD, vars[i]);
                if(args[i].getInternalName().equals("java/lang/Class")) {
                    classVar = vars[i];
                } else if (args[i].getInternalName().equals("java/net/InetSocketAddress")) {
                    socketVar = vars[i];
                }
            } else if(args[i].getSort() == Type.DOUBLE) {
                super.visitVarInsn(Opcodes.DLOAD, vars[i]);
            } else if(args[i].getSort() == Type.LONG) {
                super.visitVarInsn(Opcodes.LLOAD, vars[i]);
            } else if(args[i].getSort() == Type.FLOAT) {
                super.visitVarInsn(Opcodes.FLOAD, vars[i]);
            } else if(args[i].getSort() == Type.INT || args[i].getSort() == Type.SHORT
                    || args[i].getSort() == Type.BYTE || args[i].getSort() == Type.CHAR
                    || args[i].getSort() == Type.BOOLEAN) {
                super.visitVarInsn(ILOAD, vars[i]);
            } else {
                //this would not happen
            }
        }
        for(int i = 0; i < vars.length; i++) {
            lvs.freeTmpLV(vars[i]);
        }
        lvs.freeTmpLV(addrstr);
    }

    public void visitMethodInsn(int opcode, String owner, String name, String desc, boolean isInterface) {
    	if(this.owner.endsWith("DFSAdmin") && this.name.startsWith("setSafeMode")
    			&& (name.startsWith("setSafeMode")
    					|| name.startsWith("getProxiesForAllNameNodesInNameservice"))) {
    		super.visitLdcInsn(name+desc);
    		super.visitMethodInsn(INVOKESTATIC,
    				"java/crashfuzz/instrumenter/hdfs/HDFSInstrument", "recordString", "(Ljava/lang/String;)V", false);
    	}
        if(Configuration.USE_FAV && Configuration.FOR_HDFS || Configuration.HDFS_RPC) {
            if(HDFSProtocols.isHDFSProtocol(owner)) {
                //generate message id and record rpc call at client side
                String requestType = HDFSProtocols.getRequestProtoInternalTypeFromDesc(desc);
//                System.out.println("!!!!!!!!!GY "+this.owner+"."+this.name);
                Type[] argTypes = Type.getArgumentTypes(desc);
                int[] vars = new int[argTypes.length];

	            for(int i = argTypes.length - 1; i >= 0; i--) {
	                vars[i] = lvs.getTmpLV();
	                if(argTypes[i].getSort() == Type.OBJECT || argTypes[i].getSort() == Type.ARRAY) {
	                    super.visitVarInsn(ASTORE, vars[i]);
	                } else if(argTypes[i].getSort() == Type.DOUBLE) {
	                    super.visitVarInsn(Opcodes.DSTORE, vars[i]);
	                } else if(argTypes[i].getSort() == Type.LONG) {
	                    super.visitVarInsn(Opcodes.LSTORE, vars[i]);
	                } else if(argTypes[i].getSort() == Type.FLOAT) {
	                    super.visitVarInsn(Opcodes.FSTORE, vars[i]);
	                } else if(argTypes[i].getSort() == Type.INT || argTypes[i].getSort() == Type.SHORT
	                        || argTypes[i].getSort() == Type.BYTE || argTypes[i].getSort() == Type.CHAR
	                        || argTypes[i].getSort() == Type.BOOLEAN) {
	                    super.visitVarInsn(ISTORE, vars[i]);
	                } else {
	                    //this would not happen
	                }
	            }
	            int protocol = lvs.getTmpLV();
	            super.visitVarInsn(ASTORE, protocol);
	            super.visitVarInsn(ALOAD, protocol);
	            for(int i = 0; i < argTypes.length; i++) {
	                if(argTypes[i].getSort() == Type.OBJECT || argTypes[i].getSort() == Type.ARRAY) {
	                    super.visitVarInsn(ALOAD, vars[i]);
	                } else if(argTypes[i].getSort() == Type.DOUBLE) {
	                    super.visitVarInsn(Opcodes.DLOAD, vars[i]);
	                } else if(argTypes[i].getSort() == Type.LONG) {
	                    super.visitVarInsn(Opcodes.LLOAD, vars[i]);
	                } else if(argTypes[i].getSort() == Type.FLOAT) {
	                    super.visitVarInsn(Opcodes.FLOAD, vars[i]);
	                } else if(argTypes[i].getSort() == Type.INT || argTypes[i].getSort() == Type.SHORT
	                        || argTypes[i].getSort() == Type.BYTE || argTypes[i].getSort() == Type.CHAR
	                        || argTypes[i].getSort() == Type.BOOLEAN) {
	                    super.visitVarInsn(ILOAD, vars[i]);
	                } else {
	                    //this would not happen
	                }
	            }
//	            super.visitLdcInsn(owner+"."+name);
//	            super.visitMethodInsn(INVOKESTATIC, "java/crashfuzz/instrumenter/yarn/YarnInstrument",
//	                    "recordString", "(Ljava/lang/String;)V", false);
                recordOrTriggerRpcRequest(protocol, requestType);
                for(int i = 0; i < vars.length; i++) {
	                lvs.freeTmpLV(vars[i]);
	            }
	            lvs.freeTmpLV(protocol);
            }

            if(this.owner.startsWith("org/apache/hadoop")
                    && !this.owner.equals("org/apache/hadoop/ipc/RPC")
                    && this.name.equals("<init>") //TODO: several protocols do not get proxy in <init>
                    && owner.equals("org/apache/hadoop/ipc/RPC")
                    && (name.startsWith("getProxy") || name.startsWith("getProtocolProxy")
                            || name.startsWith("waitForProtocolProxy") || name.startsWith("waitForProxy"))
                    && opcode == Opcodes.INVOKESTATIC) {
                // checkAndStoreRpcSocket(desc);
            }
        }

        super.visitMethodInsn(opcode, owner, name, desc, isInterface);

        if(Configuration.USE_FAV && Configuration.HDFS_RPC) {
            if(HDFSProtocols.isHDFSProtocol(owner)) {
                String responseType = HDFSProtocols.getResponseProtoInternalTypeFromDesc(desc);
                int wrappedRes = lvs.getTmpLV();
                super.visitVarInsn(ASTORE, wrappedRes);
                super.visitVarInsn(ALOAD, wrappedRes);
                super.visitFieldInsn(GETFIELD, Type.getInternalName(TaintedReferenceWithObjTag.class), "val", "Ljava/lang/Object;");
                super.visitTypeInsn(CHECKCAST, responseType);
                int res = lvs.getTmpLV();
                super.visitVarInsn(ASTORE, res);
                attachTaintTagsToMessage(res, responseType, this.owner, this.name, this.desc, FAVTaintType.RPC.toString(), FAVTagType.APP.toString(), false);
                super.visitVarInsn(ALOAD, wrappedRes);
                super.visitVarInsn(ALOAD, res);
                super.visitFieldInsn(PUTFIELD, Type.getInternalName(TaintedReferenceWithObjTag.class), "val", "Ljava/lang/Object;");
                super.visitVarInsn(ALOAD, wrappedRes);
                lvs.freeTmpLV(wrappedRes);
                lvs.freeTmpLV(res);
            }
        }
    }

    public void recordOrTriggerRpcRequest(int protocol, String msgInternalT) {
        int response = lvs.getTmpLV();
        super.visitVarInsn(Opcodes.ASTORE, response);
        int rtnholder = lvs.getTmpLV();
        super.visitVarInsn(Opcodes.ASTORE, rtnholder);
        int requestTaint = lvs.getTmpLV();
        super.visitVarInsn(Opcodes.ASTORE, requestTaint);
        int request = lvs.getTmpLV();
        super.visitVarInsn(Opcodes.ASTORE, request);

        int msgid = -1;
        if(Configuration.IS_THIRD_PARTY_PROTO) {
        	//add msg id to request
            super.visitMethodInsn(INVOKESTATIC, "org/apache/hadoop/thirdparty/protobuf/UnknownFieldSet$Field",
                    "newBuilder", "()Lorg/apache/hadoop/thirdparty/protobuf/UnknownFieldSet$Field$Builder;", false);
            FAV_NEW_MSGID.delegateVisit(mv);
            msgid = lvs.getTmpLV();
            super.visitVarInsn(ISTORE, msgid);
            FAV_CURRENT_IP.delegateVisit(mv);
            super.visitVarInsn(ILOAD, msgid);
            super.visitMethodInsn(INVOKESTATIC, "java/crashfuzz/instrumenter/yarn/YarnInstrument",
                    "combineIpWithMsgid", "(Ljava/lang/String;I)Ljava/lang/String;", false);
            super.visitMethodInsn(INVOKEVIRTUAL, "java/lang/String", "getBytes", "()[B", false);
            super.visitMethodInsn(INVOKESTATIC, "org/apache/hadoop/thirdparty/protobuf/ByteString", "copyFrom", "([B)Lorg/apache/hadoop/thirdparty/protobuf/ByteString;", false);
            super.visitMethodInsn(INVOKEVIRTUAL, "org/apache/hadoop/thirdparty/protobuf/UnknownFieldSet$Field$Builder",
                    "addLengthDelimited", "(Lorg/apache/hadoop/thirdparty/protobuf/ByteString;)Lorg/apache/hadoop/thirdparty/protobuf/UnknownFieldSet$Field$Builder;", false);
            super.visitMethodInsn(INVOKEVIRTUAL, "org/apache/hadoop/thirdparty/protobuf/UnknownFieldSet$Field$Builder",
                    "build", "()Lorg/apache/hadoop/thirdparty/protobuf/UnknownFieldSet$Field;", false);
            int field = lvs.getTmpLV();
            super.visitVarInsn(ASTORE, field);
            super.visitMethodInsn(INVOKESTATIC, "org/apache/hadoop/thirdparty/protobuf/UnknownFieldSet",
                    "newBuilder", "()Lorg/apache/hadoop/thirdparty/protobuf/UnknownFieldSet$Builder;", false);
            super.visitIntInsn(Opcodes.SIPUSH, Configuration.PROTO_MSG_ID_TAG);
            super.visitVarInsn(ALOAD, field);
            super.visitMethodInsn(INVOKEVIRTUAL, "org/apache/hadoop/thirdparty/protobuf/UnknownFieldSet$Builder",
                    "addField", "(ILorg/apache/hadoop/thirdparty/protobuf/UnknownFieldSet$Field;)Lorg/apache/hadoop/thirdparty/protobuf/UnknownFieldSet$Builder;", false);
            super.visitMethodInsn(INVOKEVIRTUAL, "org/apache/hadoop/thirdparty/protobuf/UnknownFieldSet$Builder",
                    "build", "()Lorg/apache/hadoop/thirdparty/protobuf/UnknownFieldSet;", false);
            int newunknown = lvs.getTmpLV();
            super.visitVarInsn(ASTORE, newunknown);
            super.visitVarInsn(ALOAD, request);
            String msgBuilderInternal = msgInternalT+"$Builder";
            super.visitMethodInsn(INVOKEVIRTUAL, msgInternalT,
                    "toBuilder", "()L"+msgBuilderInternal+";", false);
            super.visitVarInsn(ALOAD, newunknown);
//            super.visitMethodInsn(INVOKEVIRTUAL, reqBuilderInternal,
//                    "mergeUnknownFields", "(Lorg/apache/hadoop/thirdparty/protobuf/UnknownFieldSet;)L"+reqBuilderInternal+";", false);

            //hadoop-3.3.1
            super.visitMethodInsn(INVOKEVIRTUAL, msgBuilderInternal,
                    "mergeUnknownFields", "(Lorg/apache/hadoop/thirdparty/protobuf/UnknownFieldSet;)L"
            +msgBuilderInternal+";", false);
            //hadoop-3.3.1 end
            super.visitTypeInsn(Opcodes.CHECKCAST,msgBuilderInternal);

            String msgDesc = "L"+msgInternalT+";";
            super.visitMethodInsn(INVOKEVIRTUAL, msgBuilderInternal,
                    "build", "()"+msgDesc, false);
            super.visitVarInsn(ASTORE, request);

            lvs.freeTmpLV(field);
            lvs.freeTmpLV(newunknown);
        } else {
        	//add msg id to request
            super.visitMethodInsn(INVOKESTATIC, "com/google/protobuf/UnknownFieldSet$Field",
                    "newBuilder", "()Lcom/google/protobuf/UnknownFieldSet$Field$Builder;", false);
            FAV_NEW_MSGID.delegateVisit(mv);
            msgid = lvs.getTmpLV();
            super.visitVarInsn(ISTORE, msgid);
            FAV_CURRENT_IP.delegateVisit(mv);
            super.visitVarInsn(ILOAD, msgid);
            super.visitMethodInsn(INVOKESTATIC, "java/crashfuzz/instrumenter/yarn/YarnInstrument",
                    "combineIpWithMsgid", "(Ljava/lang/String;I)Ljava/lang/String;", false);
            super.visitMethodInsn(INVOKEVIRTUAL, "java/lang/String", "getBytes", "()[B", false);
            super.visitMethodInsn(INVOKESTATIC, "com/google/protobuf/ByteString", "copyFrom", "([B)Lcom/google/protobuf/ByteString;", false);
            super.visitMethodInsn(INVOKEVIRTUAL, "com/google/protobuf/UnknownFieldSet$Field$Builder",
                    "addLengthDelimited", "(Lcom/google/protobuf/ByteString;)Lcom/google/protobuf/UnknownFieldSet$Field$Builder;", false);
            super.visitMethodInsn(INVOKEVIRTUAL, "com/google/protobuf/UnknownFieldSet$Field$Builder",
                    "build", "()Lcom/google/protobuf/UnknownFieldSet$Field;", false);
            int field = lvs.getTmpLV();
            super.visitVarInsn(ASTORE, field);
            super.visitMethodInsn(INVOKESTATIC, "com/google/protobuf/UnknownFieldSet",
                    "newBuilder", "()Lcom/google/protobuf/UnknownFieldSet$Builder;", false);
            super.visitIntInsn(Opcodes.SIPUSH, Configuration.PROTO_MSG_ID_TAG);
            super.visitVarInsn(ALOAD, field);
            super.visitMethodInsn(INVOKEVIRTUAL, "com/google/protobuf/UnknownFieldSet$Builder",
                    "addField", "(ILcom/google/protobuf/UnknownFieldSet$Field;)Lcom/google/protobuf/UnknownFieldSet$Builder;", false);
            super.visitMethodInsn(INVOKEVIRTUAL, "com/google/protobuf/UnknownFieldSet$Builder",
                    "build", "()Lcom/google/protobuf/UnknownFieldSet;", false);
            int newunknown = lvs.getTmpLV();
            super.visitVarInsn(ASTORE, newunknown);
            super.visitVarInsn(ALOAD, request);
            String msgBuilderInternal = msgInternalT+"$Builder";
            super.visitMethodInsn(INVOKEVIRTUAL, msgInternalT,
                    "toBuilder", "()L"+msgBuilderInternal+";", false);
            super.visitVarInsn(ALOAD, newunknown);
//            super.visitMethodInsn(INVOKEVIRTUAL, reqBuilderInternal,
//                    "mergeUnknownFields", "(Lcom/google/protobuf/UnknownFieldSet;)L"+reqBuilderInternal+";", false);

            //hadoop-3.2.2
             super.visitMethodInsn(INVOKEVIRTUAL, msgBuilderInternal,
                     "mergeUnknownFields", "(Lcom/google/protobuf/UnknownFieldSet;)Lcom/google/protobuf/GeneratedMessage$Builder;", false);
            //hadoop-3.2.2 end
            super.visitTypeInsn(Opcodes.CHECKCAST,msgBuilderInternal);

            String msgDesc = "L"+msgInternalT+";";
            super.visitMethodInsn(INVOKEVIRTUAL, msgBuilderInternal,
                    "build", "()"+msgDesc, false);
            super.visitVarInsn(ASTORE, request);

            lvs.freeTmpLV(field);
            lvs.freeTmpLV(newunknown);
        }

        if(Configuration.USE_FAV && Configuration.FOR_HDFS) {
            FAV_GET_RECORD_OUT.delegateVisit(mv);
            int fileOutStream = lvs.getTmpLV();
            super.visitVarInsn(Opcodes.ASTORE, fileOutStream);

            Label nullOutStream = new Label();
            FrameNode fn = getCurrentFrameNode();
            super.visitVarInsn(Opcodes.ALOAD, fileOutStream);
            super.visitJumpInsn(Opcodes.IFNULL, nullOutStream);

            super.visitVarInsn(Opcodes.ALOAD, fileOutStream);
            super.visitLdcInsn(0);  //set FAV_RECORD_TAG to false, avoid dead loop
            super.visitFieldInsn(Opcodes.PUTFIELD, "java/io/FileOutputStream", TaintUtils.FAV_RECORD_TAG, "Z");

            super.visitLabel(nullOutStream);
            acceptFn(fn);

            FAV_GET_TIMESTAMP.delegateVisit(mv);
            super.visitVarInsn(Opcodes.ALOAD, fileOutStream);
            // super.visitVarInsn(ALOAD, 0);
            // super.visitFieldInsn(GETFIELD, this.owner, TaintUtils.FAV_RPC_SOCKET, "Ljava/lang/String;");
            super.visitVarInsn(ALOAD, protocol);
            super.visitMethodInsn(INVOKESTATIC, "org/apache/hadoop/ipc/RPC", "getServerAddress", "(Ljava/lang/Object;)Ljava/net/InetSocketAddress;", false);
            super.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/net/InetSocketAddress", "getAddress", "()Ljava/net/InetAddress;", false);
            super.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/net/InetAddress", "getHostAddress", "()Ljava/lang/String;", false);
            super.visitVarInsn(ILOAD, msgid);
            super.visitMethodInsn(INVOKESTATIC, "java/crashfuzz/instrumenter/yarn/YarnInstrument",
                    "combineIpWithMsgid", "(Ljava/lang/String;I)Ljava/lang/String;", false);
            super.visitVarInsn(Opcodes.ALOAD, request);
            super.visitTypeInsn(Opcodes.CHECKCAST, msgInternalT);
            NEW_EMPTY_TAINT.delegateVisit(mv);
            super.visitTypeInsn(Opcodes.NEW, Type.getInternalName(TaintedReferenceWithObjTag.class));
            super.visitInsn(Opcodes.DUP);
            super.visitMethodInsn(Opcodes.INVOKESPECIAL, Type.getInternalName(TaintedReferenceWithObjTag.class), "<init>", "()V", false);
            super.visitMethodInsn(Opcodes.INVOKEVIRTUAL,
                    msgInternalT,
                    "toByteArray$$PHOSPHORTAGGED",
                    "("+Configuration.TAINT_TAG_DESC+Configuration.TAINTED_REF_OBJTAG_DESC+")"
                    +Configuration.TAINTED_REF_OBJTAG_DESC, false);
            super.visitFieldInsn(Opcodes.GETFIELD, Type.getInternalName(TaintedReferenceWithObjTag.class), "val", "Ljava/lang/Object;");
            super.visitTypeInsn(Opcodes.CHECKCAST, Type.getInternalName(LazyByteArrayObjTags.class));
            FAV_APP_RECORD_OR_TRIGGER_FULLY.delegateVisit(mv);
            lvs.freeTmpLV(fileOutStream);
        }

        super.visitVarInsn(Opcodes.ALOAD, request);
        super.visitVarInsn(Opcodes.ALOAD, requestTaint);
        super.visitVarInsn(Opcodes.ALOAD, rtnholder);
        super.visitVarInsn(Opcodes.ALOAD, response);

        lvs.freeTmpLV(request);
        lvs.freeTmpLV(requestTaint);
        lvs.freeTmpLV(rtnholder);
        lvs.freeTmpLV(response);
        if(msgid != -1) {
        	lvs.freeTmpLV(msgid);
        }
    }

    public void visitInsn(int opcode) {
        //use lvs would introduce errors, avoid to use lvs
        if(opcode == ARETURN) {
            recordOrTaintResponse(opcode);
        }
        super.visitInsn(opcode);
    }

    private void recordOrTaintResponse(int opcode) {
        if(Configuration.USE_FAV && Configuration.FOR_HDFS || Configuration.HDFS_RPC) {
            if(HDFSProtocols.isServerSideRpcCall(this.owner, this.name, this.desc,
                    this.ownerSuperCname, this.ownerInterfaces)) {
                String responseType = HDFSProtocols.getResponseProtoInternalTypeFromDesc(desc);
                recordOrTriggerRpcResponse(responseType);
            }
        }
    }

    public void recordOrTriggerRpcResponse(String msgInternalT) {
        //[rtn]
        super.visitInsn(DUP);
        //[rtn, rtn]
        super.visitTypeInsn(CHECKCAST, Type.getInternalName(TaintedReferenceWithObjTag.class));
        //[rtn, rtn]
        super.visitFieldInsn(GETFIELD, Type.getInternalName(TaintedReferenceWithObjTag.class), "val", "Ljava/lang/Object;");
        //[rtn, rtn.val]
        super.visitTypeInsn(Opcodes.CHECKCAST, msgInternalT);
        //[rtn, rtn.val]
        int response = lvs.getTmpLV();
        super.visitVarInsn(ASTORE, response);

        super.visitInsn(Opcodes.DUP);
        super.visitVarInsn(ALOAD, response);
        //[rtn, rtn, rtn.val]

        FAV_NEW_MSGID.delegateVisit(mv);
        int msgid = lvs.getTmpLV();
        super.visitVarInsn(ISTORE, msgid);
        //[response]
        if(Configuration.IS_THIRD_PARTY_PROTO) {
        	super.visitMethodInsn(INVOKESTATIC, "org/apache/hadoop/thirdparty/protobuf/UnknownFieldSet",
                    "newBuilder", "()Lorg/apache/hadoop/thirdparty/protobuf/UnknownFieldSet$Builder;", false);
            super.visitIntInsn(Opcodes.SIPUSH, Configuration.PROTO_MSG_ID_TAG);
            //[response, UnknownFieldSet$Builder, msgTag]
            super.visitMethodInsn(INVOKESTATIC, "org/apache/hadoop/thirdparty/protobuf/UnknownFieldSet$Field",
                    "newBuilder", "()Lorg/apache/hadoop/thirdparty/protobuf/UnknownFieldSet$Field$Builder;", false);
            FAV_CURRENT_IP.delegateVisit(mv);
//            FAV_NEW_MSGID.delegateVisit(mv);
//            int msgid = lvs.getTmpLV();
//            super.visitVarInsn(ISTORE, msgid);
            super.visitVarInsn(ILOAD, msgid);
            super.visitMethodInsn(INVOKESTATIC, "java/crashfuzz/instrumenter/yarn/YarnInstrument",
                    "combineIpWithMsgid", "(Ljava/lang/String;I)Ljava/lang/String;", false);
            super.visitMethodInsn(INVOKEVIRTUAL, "java/lang/String", "getBytes", "()[B", false);
            super.visitMethodInsn(INVOKESTATIC, "org/apache/hadoop/thirdparty/protobuf/ByteString", "copyFrom", "([B)Lorg/apache/hadoop/thirdparty/protobuf/ByteString;", false);
            super.visitMethodInsn(INVOKEVIRTUAL, "org/apache/hadoop/thirdparty/protobuf/UnknownFieldSet$Field$Builder",
                    "addLengthDelimited", "(Lorg/apache/hadoop/thirdparty/protobuf/ByteString;)Lorg/apache/hadoop/thirdparty/protobuf/UnknownFieldSet$Field$Builder;", false);
            super.visitMethodInsn(INVOKEVIRTUAL, "org/apache/hadoop/thirdparty/protobuf/UnknownFieldSet$Field$Builder",
                    "build", "()Lorg/apache/hadoop/thirdparty/protobuf/UnknownFieldSet$Field;", false);
            //[response, UnknownFieldSet$Builder, msgTag, Field]
            super.visitMethodInsn(INVOKEVIRTUAL, "org/apache/hadoop/thirdparty/protobuf/UnknownFieldSet$Builder",
                    "addField", "(ILorg/apache/hadoop/thirdparty/protobuf/UnknownFieldSet$Field;)Lorg/apache/hadoop/thirdparty/protobuf/UnknownFieldSet$Builder;", false);
            super.visitMethodInsn(INVOKEVIRTUAL, "org/apache/hadoop/thirdparty/protobuf/UnknownFieldSet$Builder",
                    "build", "()Lorg/apache/hadoop/thirdparty/protobuf/UnknownFieldSet;", false);
            //[response, UnknownFieldSet]
            super.visitInsn(SWAP);
            //[UnknownFieldSet, response]
            String msgBuilderInternal = msgInternalT+"$Builder";
            super.visitMethodInsn(INVOKEVIRTUAL, msgInternalT,
                    "toBuilder", "()L"+msgBuilderInternal+";", false);
            //[UnknownFieldSet, response$builder]
            super.visitInsn(SWAP);
            //[response$builder, UnknownFieldSet]
//          super.visitMethodInsn(INVOKEVIRTUAL, reqBuilderInternal,
//          "mergeUnknownFields", "(Lorg/apache/hadoop/thirdparty/protobuf/UnknownFieldSet;)L"+reqBuilderInternal+";", false);

            //hadoop-3.3.1
            super.visitMethodInsn(INVOKEVIRTUAL, msgBuilderInternal,
                    "mergeUnknownFields", "(Lorg/apache/hadoop/thirdparty/protobuf/UnknownFieldSet;)L"
            +msgBuilderInternal+";", false);
            //hadoop-3.3.1 end
            super.visitTypeInsn(Opcodes.CHECKCAST,msgBuilderInternal);
            String msgDesc = "L"+msgInternalT+";";
            super.visitMethodInsn(INVOKEVIRTUAL, msgBuilderInternal, "build", "()"+msgDesc, false);
            //[newresponse]

            //[rtn, rtn, newResponse]
            super.visitFieldInsn(PUTFIELD, Type.getInternalName(TaintedReferenceWithObjTag.class), "val", "Ljava/lang/Object;");
            //[rtn]
        } else {
        	super.visitMethodInsn(INVOKESTATIC, "com/google/protobuf/UnknownFieldSet",
                    "newBuilder", "()Lcom/google/protobuf/UnknownFieldSet$Builder;", false);
            super.visitIntInsn(Opcodes.SIPUSH, Configuration.PROTO_MSG_ID_TAG);
            //[response, UnknownFieldSet$Builder, msgTag]
            super.visitMethodInsn(INVOKESTATIC, "com/google/protobuf/UnknownFieldSet$Field",
                    "newBuilder", "()Lcom/google/protobuf/UnknownFieldSet$Field$Builder;", false);
            FAV_CURRENT_IP.delegateVisit(mv);
//            FAV_NEW_MSGID.delegateVisit(mv);
//            int msgid = lvs.getTmpLV();
//            super.visitVarInsn(ISTORE, msgid);
            super.visitVarInsn(ILOAD, msgid);
            super.visitMethodInsn(INVOKESTATIC, "java/crashfuzz/instrumenter/yarn/YarnInstrument",
                    "combineIpWithMsgid", "(Ljava/lang/String;I)Ljava/lang/String;", false);
            super.visitMethodInsn(INVOKEVIRTUAL, "java/lang/String", "getBytes", "()[B", false);
            super.visitMethodInsn(INVOKESTATIC, "com/google/protobuf/ByteString", "copyFrom", "([B)Lcom/google/protobuf/ByteString;", false);
            super.visitMethodInsn(INVOKEVIRTUAL, "com/google/protobuf/UnknownFieldSet$Field$Builder",
                    "addLengthDelimited", "(Lcom/google/protobuf/ByteString;)Lcom/google/protobuf/UnknownFieldSet$Field$Builder;", false);
            super.visitMethodInsn(INVOKEVIRTUAL, "com/google/protobuf/UnknownFieldSet$Field$Builder",
                    "build", "()Lcom/google/protobuf/UnknownFieldSet$Field;", false);
            //[response, UnknownFieldSet$Builder, msgTag, Field]
            super.visitMethodInsn(INVOKEVIRTUAL, "com/google/protobuf/UnknownFieldSet$Builder",
                    "addField", "(ILcom/google/protobuf/UnknownFieldSet$Field;)Lcom/google/protobuf/UnknownFieldSet$Builder;", false);
            super.visitMethodInsn(INVOKEVIRTUAL, "com/google/protobuf/UnknownFieldSet$Builder",
                    "build", "()Lcom/google/protobuf/UnknownFieldSet;", false);
            //[response, UnknownFieldSet]
            super.visitInsn(SWAP);
            //[UnknownFieldSet, response]
            String msgBuilderInternal = msgInternalT+"$Builder";
            super.visitMethodInsn(INVOKEVIRTUAL, msgInternalT,
                    "toBuilder", "()L"+msgBuilderInternal+";", false);
            //[UnknownFieldSet, response$builder]
            super.visitInsn(SWAP);
            //[response$builder, UnknownFieldSet]
//          super.visitMethodInsn(INVOKEVIRTUAL, reqBuilderInternal,
//          "mergeUnknownFields", "(Lcom/google/protobuf/UnknownFieldSet;)L"+reqBuilderInternal+";", false);

            //hadoop-3.2.2
             super.visitMethodInsn(INVOKEVIRTUAL, msgBuilderInternal,
           "mergeUnknownFields", "(Lcom/google/protobuf/UnknownFieldSet;)Lcom/google/protobuf/GeneratedMessage$Builder;", false);
            //hadoop-3.2.2 end
            super.visitTypeInsn(Opcodes.CHECKCAST,msgBuilderInternal);
            String msgDesc = "L"+msgInternalT+";";
            super.visitMethodInsn(INVOKEVIRTUAL, msgBuilderInternal, "build", "()"+msgDesc, false);
            //[newresponse]

            //[rtn, rtn, newResponse]
            super.visitFieldInsn(PUTFIELD, Type.getInternalName(TaintedReferenceWithObjTag.class), "val", "Ljava/lang/Object;");
            //[rtn]
        }

        if(Configuration.USE_FAV && Configuration.FOR_HDFS) {
        	FAV_GET_RECORD_OUT.delegateVisit(mv);
            int fileOutStream = lvs.getTmpLV();
            super.visitVarInsn(Opcodes.ASTORE, fileOutStream);

            Label nullOutStream = new Label();
            FrameNode fn = getCurrentFrameNode();
            super.visitVarInsn(Opcodes.ALOAD, fileOutStream);
            super.visitJumpInsn(Opcodes.IFNULL, nullOutStream);

            super.visitVarInsn(Opcodes.ALOAD, fileOutStream);
            super.visitLdcInsn(0);  //set FAV_RECORD_TAG to false, avoid dead loop
            super.visitFieldInsn(Opcodes.PUTFIELD, "java/io/FileOutputStream", TaintUtils.FAV_RECORD_TAG, "Z");

            super.visitLabel(nullOutStream);
            acceptFn(fn);

            FAV_GET_TIMESTAMP.delegateVisit(mv);
            super.visitVarInsn(Opcodes.ALOAD, fileOutStream);
            //get remote ip from remoteIpVar
            super.visitVarInsn(ALOAD, remoteIpVar);
            super.visitVarInsn(ILOAD, msgid);
            super.visitMethodInsn(INVOKESTATIC, "java/crashfuzz/instrumenter/yarn/YarnInstrument",
                    "combineIpWithMsgid", "(Ljava/lang/String;I)Ljava/lang/String;", false);
            super.visitVarInsn(Opcodes.ALOAD, response);
            NEW_EMPTY_TAINT.delegateVisit(mv);
            super.visitTypeInsn(Opcodes.NEW, Type.getInternalName(TaintedReferenceWithObjTag.class));
            super.visitInsn(Opcodes.DUP);
            super.visitMethodInsn(Opcodes.INVOKESPECIAL, Type.getInternalName(TaintedReferenceWithObjTag.class), "<init>", "()V", false);
            super.visitMethodInsn(Opcodes.INVOKEVIRTUAL,
                    msgInternalT,
                    "toByteArray$$PHOSPHORTAGGED",
                    "("+Configuration.TAINT_TAG_DESC+Configuration.TAINTED_REF_OBJTAG_DESC+")"
                    +Configuration.TAINTED_REF_OBJTAG_DESC, false);
            super.visitFieldInsn(Opcodes.GETFIELD, Type.getInternalName(TaintedReferenceWithObjTag.class), "val", "Ljava/lang/Object;");
            super.visitTypeInsn(Opcodes.CHECKCAST, Type.getInternalName(LazyByteArrayObjTags.class));
            FAV_APP_RECORD_OR_TRIGGER_FULLY.delegateVisit(mv);
            //[rtn]

            lvs.freeTmpLV(fileOutStream);
        }

        lvs.freeTmpLV(response);
        lvs.freeTmpLV(msgid);
    }

}
