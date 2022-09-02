package java.crashfuzz.instrumenter;


import edu.columbia.cs.psl.phosphor.instrumenter.TaintAdapter;
import edu.columbia.cs.psl.phosphor.instrumenter.analyzer.NeverNullArgAnalyzerAdapter;
import edu.columbia.cs.psl.phosphor.runtime.Taint;

import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.Label;
import org.objectweb.asm.tree.FrameNode;

import edu.columbia.cs.psl.phosphor.Configuration;
import edu.columbia.cs.psl.phosphor.TaintUtils;
import edu.columbia.cs.psl.phosphor.struct.LazyByteArrayObjTags;
import java.crashfuzz.taint.FAVTaintType;
import java.crashfuzz.taint.Source.FAVTagType;
import java.crashfuzz.tracing.FAVPathType;

import static edu.columbia.cs.psl.phosphor.instrumenter.TaintMethodRecord.*;

import java.util.Arrays;
import java.util.List;

//model use of zookeeper, as a client
public class ZKAPIModelMV extends TaintAdapter implements Opcodes {
    private final String desc;
    private final Type returnType;
    private final String name;
    private final boolean isStatic;
    private final boolean isPublic;
    private final String owner;
    private final String ownerSuperCname;
    private final String[] ownerInterfaces;

    //take znode path as path, znode value as value, record value taint to path
    //specifically record delete operation with taint empty
    //take every return value of every public method as a read
    public ZKAPIModelMV(MethodVisitor mv, int access, String owner, String name, String descriptor, String signature,
            String[] exceptions, String originalDesc, NeverNullArgAnalyzerAdapter analyzer, String ownerSuperCname, String[] ownerInterfaces) {
        super(access, owner, name, descriptor, signature, exceptions, mv, analyzer);
        this.desc = descriptor;
        this.returnType = Type.getReturnType(desc);
        this.isStatic = (access & Opcodes.ACC_STATIC) != 0;
        this.isPublic = (access & Opcodes.ACC_PUBLIC) != 0;
        this.name = name;
        this.owner = owner;
        this.ownerSuperCname = ownerSuperCname;
        this.ownerInterfaces = ownerInterfaces;
    }

    public void visitCode() {
    	if(Configuration.USE_FAV && Configuration.ZK_API) {
    		List<String> inters =  Arrays.asList(this.ownerInterfaces);
        	if((this.ownerSuperCname.equals("org/apache/zookeeper/AsyncCallback$DataCallback") || inters.contains("org/apache/zookeeper/AsyncCallback$DataCallback"))
        			&& this.name.startsWith("processResult") && this.desc.startsWith("("+Configuration.TAINT_TAG_DESC
        					+"I"+Configuration.TAINT_TAG_DESC+"Ljava/lang/String;"+Configuration.TAINT_TAG_DESC
        					+"Ljava/lang/Object;"+Configuration.TAINT_TAG_DESC+Type.getDescriptor(LazyByteArrayObjTags.class))) {
        		super.visitVarInsn(ALOAD, 8);
        		super.visitLdcInsn(className);
            	super.visitLdcInsn(this.name);
            	super.visitLdcInsn(desc);
            	super.visitLdcInsn(FAVTaintType.RPC.toString());
            	super.visitLdcInsn(FAVTagType.APP.toString());
            	super.visitTypeInsn(Opcodes.NEW, "java/lang/StringBuilder");
                super.visitInsn(Opcodes.DUP);
                super.visitLdcInsn(FAVPathType.ZK.toString()+":");
                super.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/StringBuilder", "<init>", "(Ljava/lang/String;)V", false);
                super.visitVarInsn(ALOAD, 4);
                super.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/StringBuilder", "append", "(Ljava/lang/String;)Ljava/lang/StringBuilder;", false);
                super.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/StringBuilder", "toString", "()Ljava/lang/String;", false);
                FAV_APP_TAINT_BYTES_FULLY.delegateVisit(mv);
                super.visitVarInsn(ASTORE, 8);
        	} else if (this.owner.equals("org/apache/hadoop/util/curator/ZKCuratorManager")) {
        		if((this.name.startsWith("create"+TaintUtils.METHOD_SUFFIX)
        				&& this.desc.startsWith("("+Configuration.TAINT_TAG_DESC+"Ljava/lang/String;"
        				+Configuration.TAINT_TAG_DESC+"Ljava/util/List;"))
        				//public boolean create(final String path, List<ACL> zkAcl)
        				|| (this.name.startsWith("delete"+TaintUtils.METHOD_SUFFIX) && this.desc.startsWith("("+Configuration.TAINT_TAG_DESC+"Ljava/lang/String;"))
        				//public boolean delete(final String path)
        				|| (this.name.startsWith("setData"+TaintUtils.METHOD_SUFFIX) && this.desc.startsWith("("+Configuration.TAINT_TAG_DESC+"Ljava/lang/String;"
                				+Configuration.TAINT_TAG_DESC+Type.getDescriptor(LazyByteArrayObjTags.class)))
        				//public void setData(String path, byte[] data, int version)
        				|| (this.name.startsWith("safeCreate"+TaintUtils.METHOD_SUFFIX)
                				&& this.desc.startsWith("("+Configuration.TAINT_TAG_DESC+"Ljava/lang/String;"
                        				+Configuration.TAINT_TAG_DESC+Type.getDescriptor(LazyByteArrayObjTags.class)))
        				//public void safeCreate(String path, byte[] data, List<ACL> acl, CreateMode mode, List<ACL> fencingACL, String fencingNodePath)
        				|| (this.name.startsWith("safeDelete"+TaintUtils.METHOD_SUFFIX) && this.desc.startsWith("("+Configuration.TAINT_TAG_DESC+"Ljava/lang/String;"))
        				//public void safeDelete(final String path, List<ACL> fencingACL, String fencingNodePath)
        				|| (this.name.startsWith("safeSetData"+TaintUtils.METHOD_SUFFIX) && this.desc.startsWith("("+Configuration.TAINT_TAG_DESC+"Ljava/lang/String;"
                				+Configuration.TAINT_TAG_DESC+Type.getDescriptor(LazyByteArrayObjTags.class)))
        				//public void safeSetData(String path, byte[] data, int version, List<ACL> fencingACL, String fencingNodePath)
        				) {
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

        	        if(name.startsWith("setData") || name.startsWith("safeSetData")) {
        	        	FAV_GET_TIMESTAMP.delegateVisit(mv);
            	        super.visitVarInsn(Opcodes.ALOAD, fileOutStream);
            	        super.visitTypeInsn(Opcodes.NEW, "java/lang/StringBuilder");
                        super.visitInsn(Opcodes.DUP);
                        super.visitLdcInsn(FAVPathType.ZK.toString()+":");
                        super.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/StringBuilder", "<init>", "(Ljava/lang/String;)V", false);
                        super.visitVarInsn(ALOAD, 2);
                        super.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/StringBuilder", "append", "(Ljava/lang/String;)Ljava/lang/StringBuilder;", false);
                        super.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/StringBuilder", "toString",
                        "()Ljava/lang/String;", false);
            	        super.visitVarInsn(ALOAD, 4);
            	        super.visitTypeInsn(Opcodes.CHECKCAST, Type.getInternalName(LazyByteArrayObjTags.class));
            	        FAV_APP_RECORD_OR_TRIGGER_FULLY.delegateVisit(mv);
        	        } else if (name.startsWith("create")) {
        	        	FAV_GET_TIMESTAMP.delegateVisit(mv);
            	        super.visitVarInsn(Opcodes.ALOAD, fileOutStream);
            	        super.visitTypeInsn(Opcodes.NEW, "java/lang/StringBuilder");
                        super.visitInsn(Opcodes.DUP);
                        super.visitLdcInsn(FAVPathType.ZK.toString()+":");
                        super.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/StringBuilder", "<init>", "(Ljava/lang/String;)V", false);
                        super.visitVarInsn(ALOAD, 2);
                        super.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/StringBuilder", "append", "(Ljava/lang/String;)Ljava/lang/StringBuilder;", false);
                        super.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/StringBuilder", "toString",
                        "()Ljava/lang/String;", false);
            	        super.visitVarInsn(ALOAD, 3);
            	        super.visitVarInsn(ALOAD, 2);
           	            super.visitMethodInsn(INVOKEVIRTUAL, "java/lang/String", "fav" + TaintUtils.TAINT_FIELD, "()Ljava/lang/Object;", false);
           	            super.visitTypeInsn(Opcodes.CHECKCAST, Configuration.TAINT_TAG_INTERNAL_NAME);
           	            COMBINE_TAGS.delegateVisit(mv);
            	        FAV_APP_RECORD_OR_TRIGGER_TAINT.delegateVisit(mv);
        	        } else if (name.startsWith("safeCreate")) {//for create, the znode path is also a kind of important resource
        	        	FAV_GET_TIMESTAMP.delegateVisit(mv);
            	        super.visitVarInsn(Opcodes.ALOAD, fileOutStream);
            	        super.visitTypeInsn(Opcodes.NEW, "java/lang/StringBuilder");
                        super.visitInsn(Opcodes.DUP);
                        super.visitLdcInsn(FAVPathType.ZK.toString()+":");
                        super.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/StringBuilder", "<init>", "(Ljava/lang/String;)V", false);
                        super.visitVarInsn(ALOAD, 2);
                        super.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/StringBuilder", "append", "(Ljava/lang/String;)Ljava/lang/StringBuilder;", false);
                        super.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/StringBuilder", "toString",
                        "()Ljava/lang/String;", false);
            	        super.visitVarInsn(ALOAD, 3);
            	        super.visitVarInsn(ALOAD, 2);
           	            super.visitMethodInsn(INVOKEVIRTUAL, "java/lang/String", "fav" + TaintUtils.TAINT_FIELD, "()Ljava/lang/Object;", false);
           	            super.visitTypeInsn(Opcodes.CHECKCAST, Configuration.TAINT_TAG_INTERNAL_NAME);
           	            COMBINE_TAGS.delegateVisit(mv);
           	            super.visitVarInsn(ALOAD, 4);
         	            super.visitTypeInsn(Opcodes.CHECKCAST, Type.getInternalName(LazyByteArrayObjTags.class));
         	            super.visitFieldInsn(GETFIELD, Type.getInternalName(LazyByteArrayObjTags.class), "taints", "["+Configuration.TAINT_TAG_DESC);
         	            COMBINE_TAGS_ARRAY.delegateVisit(mv);
         	            COMBINE_TAGS.delegateVisit(mv);
            	        FAV_APP_RECORD_OR_TRIGGER_TAINT.delegateVisit(mv);
        	        } else if (name.startsWith("delete") || name.startsWith("safeDelete")) {
        	        	FAV_GET_TIMESTAMP.delegateVisit(mv);
            	        super.visitVarInsn(Opcodes.ALOAD, fileOutStream);
            	        super.visitTypeInsn(Opcodes.NEW, "java/lang/StringBuilder");
                        super.visitInsn(Opcodes.DUP);
                        super.visitLdcInsn(FAVPathType.ZK.toString()+":");
                        super.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/StringBuilder", "<init>", "(Ljava/lang/String;)V", false);
                        super.visitVarInsn(ALOAD, 2);
                        super.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/StringBuilder", "append", "(Ljava/lang/String;)Ljava/lang/StringBuilder;", false);
                        super.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/StringBuilder", "toString",
                        "()Ljava/lang/String;", false);
            	        super.visitVarInsn(ALOAD, 3);
            	        super.visitVarInsn(ALOAD, 2);
           	            super.visitMethodInsn(INVOKEVIRTUAL, "java/lang/String", "fav" + TaintUtils.TAINT_FIELD, "()Ljava/lang/Object;", false);
           	            super.visitTypeInsn(Opcodes.CHECKCAST, Configuration.TAINT_TAG_INTERNAL_NAME);
           	            COMBINE_TAGS.delegateVisit(mv);
            	        FAV_APP_RECORD_OR_TRIGGER_TAINT.delegateVisit(mv);
        	        }

        	        lvs.freeTmpLV(fileOutStream);
        		}
        	}
    	}
        super.visitCode();
    }

    public void visitInsn(int opcode) {
        //use lvs would introduce errors, avoid to use lvs
        if(opcode == ARETURN) {
        	if(Configuration.USE_FAV && Configuration.ZK_API) {
        		if (this.owner.equals("org/apache/hadoop/util/curator/ZKCuratorManager")) {
        			if ((this.name.startsWith("getData"+TaintUtils.METHOD_SUFFIX) && this.desc.startsWith("("+Configuration.TAINT_TAG_DESC+"Ljava/lang/String;")
            				&& this.desc.contains(Type.getDescriptor(LazyByteArrayObjTags.class)))
            				//public byte[] getData(final String path
            				//TODO: public List<String> getChildren(final String path
            				) {
                        Type rtnType = Type.getReturnType(this.desc);
            			super.visitLdcInsn(className);
                    	super.visitLdcInsn(this.name);
                    	super.visitLdcInsn(desc);
                    	super.visitLdcInsn(FAVTaintType.RPC.toString());
                    	super.visitLdcInsn(FAVTagType.APP.toString());
                    	super.visitTypeInsn(Opcodes.NEW, "java/lang/StringBuilder");
                        super.visitInsn(Opcodes.DUP);
                        super.visitLdcInsn(FAVPathType.ZK.toString()+":");
                        super.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/StringBuilder", "<init>", "(Ljava/lang/String;)V", false);
                        super.visitVarInsn(ALOAD, 2);
                        super.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/StringBuilder", "append", "(Ljava/lang/String;)Ljava/lang/StringBuilder;", false);
                        super.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/StringBuilder", "toString", "()Ljava/lang/String;", false);
                        FAV_APP_TAINT_PRIMITIVE.delegateVisit(mv);
                		super.visitTypeInsn(Opcodes.CHECKCAST, rtnType.getInternalName());
            		}
        		}
        	}
        }
        super.visitInsn(opcode);
    }

    @Override
	public void visitMethodInsn(int opcode, String owner, String name, String descriptor, boolean isInterface) {
		// TODO Auto-generated method stub
    	if(Configuration.USE_FAV && Configuration.ZK_API) {
    		if(owner.equals("org/apache/zookeeper/ZooKeeper") && !this.owner.equals("org/apache/zookeeper/ZooKeeper") && !name.equals("<init>")) {
        		Type[] args = Type.getArgumentTypes(descriptor);
                int[] vars = new int[args.length];
                Type rtnType = Type.getReturnType(descriptor);
                for(int i = args.length - 1; i >= 0; i--) {
                    vars[i] = lvs.getTmpLV();
                    if(args[i].getSort() == Type.OBJECT || args[i].getSort() == Type.ARRAY) {
                        super.visitVarInsn(ASTORE, vars[i]);
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

//        		super.visitLdcInsn(this.owner+"."+this.name);
//        		super.visitLdcInsn(owner+"."+name);
//        		super.visitLdcInsn(descriptor);
//        		super.visitMethodInsn(Opcodes.INVOKESTATIC, "java/crashfuzz/instrumenter/ZKAPIModelMV",
//        				"printPath", "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V", false);

        		if(((name.startsWith("create") || name.startsWith("setData")) && descriptor.startsWith("("+Configuration.TAINT_TAG_DESC+"Ljava/lang/String;"
        				+Configuration.TAINT_TAG_DESC+Type.getDescriptor(LazyByteArrayObjTags.class)))
        				|| (name.startsWith("delete") && descriptor.startsWith("("+Configuration.TAINT_TAG_DESC+"Ljava/lang/String;"))) {
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

        	        if(name.startsWith("setData")) {
        	        	FAV_GET_TIMESTAMP.delegateVisit(mv);
            	        super.visitVarInsn(Opcodes.ALOAD, fileOutStream);
            	        super.visitTypeInsn(Opcodes.NEW, "java/lang/StringBuilder");
                        super.visitInsn(Opcodes.DUP);
                        super.visitLdcInsn(FAVPathType.ZK.toString()+":");
                        super.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/StringBuilder", "<init>", "(Ljava/lang/String;)V", false);
                        super.visitVarInsn(ALOAD, vars[1]);
                        super.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/StringBuilder", "append", "(Ljava/lang/String;)Ljava/lang/StringBuilder;", false);
                        super.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/StringBuilder", "toString",
                        "()Ljava/lang/String;", false);
            	        super.visitVarInsn(ALOAD, vars[3]);
            	        super.visitTypeInsn(Opcodes.CHECKCAST, Type.getInternalName(LazyByteArrayObjTags.class));
            	        FAV_APP_RECORD_OR_TRIGGER_FULLY.delegateVisit(mv);
        	        } else if (name.startsWith("create")) {//for create, the znode path is also a kind of important resource
        	        	FAV_GET_TIMESTAMP.delegateVisit(mv);
            	        super.visitVarInsn(Opcodes.ALOAD, fileOutStream);
            	        super.visitTypeInsn(Opcodes.NEW, "java/lang/StringBuilder");
                        super.visitInsn(Opcodes.DUP);
                        super.visitLdcInsn(FAVPathType.ZK.toString()+":");
                        super.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/StringBuilder", "<init>", "(Ljava/lang/String;)V", false);
                        super.visitVarInsn(ALOAD, vars[1]);
                        super.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/StringBuilder", "append", "(Ljava/lang/String;)Ljava/lang/StringBuilder;", false);
                        super.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/StringBuilder", "toString",
                        "()Ljava/lang/String;", false);
            	        super.visitVarInsn(ALOAD, vars[2]);
            	        super.visitVarInsn(ALOAD, vars[1]);
           	            super.visitMethodInsn(INVOKEVIRTUAL, "java/lang/String", "fav" + TaintUtils.TAINT_FIELD, "()Ljava/lang/Object;", false);
           	            super.visitTypeInsn(Opcodes.CHECKCAST, Configuration.TAINT_TAG_INTERNAL_NAME);
           	            COMBINE_TAGS.delegateVisit(mv);
           	            super.visitVarInsn(ALOAD, vars[3]);
         	            super.visitTypeInsn(Opcodes.CHECKCAST, Type.getInternalName(LazyByteArrayObjTags.class));
         	            super.visitMethodInsn(INVOKESTATIC, "java/crashfuzz/instrumenter/ZKAPIModelMV",
         	            		"check", "("+Type.getDescriptor(LazyByteArrayObjTags.class)
         	            		+")"+Configuration.TAINT_TAG_DESC, isInterface);
//         	            super.visitFieldInsn(GETFIELD, Type.getInternalName(LazyByteArrayObjTags.class), "taints", "["+Configuration.TAINT_TAG_DESC);
//         	            super.visitInsn(POP);
//         	            COMBINE_TAGS_ARRAY.delegateVisit(mv);
         	            COMBINE_TAGS.delegateVisit(mv);
            	        FAV_APP_RECORD_OR_TRIGGER_TAINT.delegateVisit(mv);
        	        } else {
        	        	FAV_GET_TIMESTAMP.delegateVisit(mv);
            	        super.visitVarInsn(Opcodes.ALOAD, fileOutStream);
            	        super.visitTypeInsn(Opcodes.NEW, "java/lang/StringBuilder");
                        super.visitInsn(Opcodes.DUP);
                        super.visitLdcInsn(FAVPathType.ZK.toString()+":");
                        super.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/StringBuilder", "<init>", "(Ljava/lang/String;)V", false);
                        super.visitVarInsn(ALOAD, vars[1]);
                        super.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/StringBuilder", "append", "(Ljava/lang/String;)Ljava/lang/StringBuilder;", false);
                        super.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/StringBuilder", "toString",
                        "()Ljava/lang/String;", false);
            	        super.visitVarInsn(ALOAD, vars[2]);
            	        super.visitVarInsn(ALOAD, vars[1]);
           	            super.visitMethodInsn(INVOKEVIRTUAL, "java/lang/String", "fav" + TaintUtils.TAINT_FIELD, "()Ljava/lang/Object;", false);
           	            super.visitTypeInsn(Opcodes.CHECKCAST, Configuration.TAINT_TAG_INTERNAL_NAME);
           	            COMBINE_TAGS.delegateVisit(mv);
            	        FAV_APP_RECORD_OR_TRIGGER_TAINT.delegateVisit(mv);
        	        }

        	        lvs.freeTmpLV(fileOutStream);
        		}

                for(int i = 0; i < args.length; i++) {
                    if(args[i].getSort() == Type.OBJECT || args[i].getSort() == Type.ARRAY) {
                        super.visitVarInsn(ALOAD, vars[i]);
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

                super.visitMethodInsn(opcode, owner, name, descriptor, isInterface);

                if((name.startsWith("getChildren") || name.startsWith("getData")) && descriptor.startsWith("("+Configuration.TAINT_TAG_DESC+"Ljava/lang/String;")
                		&& !rtnType.equals(Type.VOID_TYPE)) {
                	super.visitLdcInsn(className);
                	super.visitLdcInsn(this.name);
                	super.visitLdcInsn(desc);
                	super.visitLdcInsn(FAVTaintType.RPC.toString());
                	super.visitLdcInsn(FAVTagType.APP.toString());
                	super.visitTypeInsn(Opcodes.NEW, "java/lang/StringBuilder");
                    super.visitInsn(Opcodes.DUP);
                    super.visitLdcInsn(FAVPathType.ZK.toString()+":");
                    super.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/StringBuilder", "<init>", "(Ljava/lang/String;)V", false);
                    super.visitVarInsn(ALOAD, vars[1]);
                    super.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/StringBuilder", "append", "(Ljava/lang/String;)Ljava/lang/StringBuilder;", false);
                    super.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/StringBuilder", "toString", "()Ljava/lang/String;", false);
                    FAV_APP_TAINT_PRIMITIVE.delegateVisit(mv);
            		super.visitTypeInsn(Opcodes.CHECKCAST, rtnType.getInternalName());
                }
                for(int i = 0; i < vars.length; i++) {
                    lvs.freeTmpLV(vars[i]);
                }
        	} else {
        		super.visitMethodInsn(opcode, owner, name, descriptor, isInterface);
        	}
    	} else {
    		super.visitMethodInsn(opcode, owner, name, descriptor, isInterface);
    	}
//    	super.visitMethodInsn(opcode, owner, name, descriptor, isInterface);
	}

    public static Taint check(LazyByteArrayObjTags taintedBytes) {
    	if(taintedBytes == null) {
    		return Taint.emptyTaint();
    	} else {
    		return Taint.combineTaintArray(taintedBytes.taints);
    	}
    }
	public static void printPath(String cname, String mname, String desc) {
        System.out.println("FAV ZK Path: "+cname+"."+mname+"."+desc);
    }

}
