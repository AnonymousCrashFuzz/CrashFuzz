package java.crashfuzz.instrumenter;


import edu.columbia.cs.psl.phosphor.Configuration;
import edu.columbia.cs.psl.phosphor.instrumenter.TaintAdapter;
import edu.columbia.cs.psl.phosphor.instrumenter.analyzer.NeverNullArgAnalyzerAdapter;

import java.util.HashSet;
import java.util.Set;

import org.objectweb.asm.Handle;
import org.objectweb.asm.Label;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
//import org.objectweb.asm.tree.FrameNode;

import java.crashfuzz.instrumenter.CoverageMap.BlockType;

//model use of zookeeper, as a client
public class CodeCoverageMV extends TaintAdapter implements Opcodes {
    private final String desc;
    private final Type returnType;
    private final String name;
    private final boolean isStatic;
    private final boolean isPublic;
    private final String owner;
    private String ownerSuperCname;
    private String[] ownerInterfaces;
    private int thisLine;
    private Set<Label> blockStartLables;
    private int blockIdx;
    private boolean skipClass;
    private Label currentLabel;
    private boolean firstInsAfterCurLabel;
    private boolean curLabelIsABlock;
    private boolean afterJumpNeedABlock;

    //take znode path as path, znode value as value, record value taint to path
    //specifically record delete operation with taint empty
    //take every return value of every public method as a read
    public CodeCoverageMV(MethodVisitor mv, int access, String owner, String name, String descriptor, String signature,
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
        this.blockStartLables = new HashSet<Label>();
        this.blockIdx = 0;
        if(this.owner.startsWith("java/io/")) {
        	skipClass = true;
        } else {
        	skipClass = false;
        }
        this.currentLabel = null;
        this.firstInsAfterCurLabel = false;
        curLabelIsABlock = false;
        afterJumpNeedABlock = false;
    }

    public CodeCoverageMV(MethodVisitor mv, int access, String owner, String name, String descriptor, String signature,
            String[] exceptions, NeverNullArgAnalyzerAdapter analyzer,
            String superCname, String[] interfaces) {
		// TODO Auto-generated constructor stub
    	super(access, owner, name, descriptor, signature, exceptions, mv, analyzer);
        this.desc = descriptor;
        this.returnType = Type.getReturnType(desc);
        this.isStatic = (access & Opcodes.ACC_STATIC) != 0;
        this.isPublic = (access & Opcodes.ACC_PUBLIC) != 0;
        this.name = name;
        this.owner = owner;
        this.blockStartLables = new HashSet<Label>();
        this.blockIdx = 0;
        if(this.owner.startsWith("java/io/")) {
        	skipClass = true;
        } else {
        	skipClass = false;
        }
        this.currentLabel = null;
        this.firstInsAfterCurLabel = false;
        curLabelIsABlock = false;
        afterJumpNeedABlock = false;
	}

	@Override
	public void visitLineNumber(int line, Label start) {
		// TODO Auto-generated method stub
		super.visitLineNumber(line, start);
		this.thisLine = line;
	}

	public void visitCode() {
        super.visitCode();
        if(Configuration.USE_FAV) {
            this.blockIdx++;
            flagThisBlock(BlockType.ENTER.toString()+this.blockIdx);
        }
    }

	@Override
	public void visitJumpInsn(int opcode, Label label) {
		// TODO Auto-generated method stub
		super.visitJumpInsn(opcode, label);
		if(Configuration.USE_FAV) {
			this.blockStartLables.add(label);
			if(opcode != Opcodes.GOTO) {
//		        this.blockIdx++;
//				flagThisBlock(BlockType.JUMP.toString()+this.blockIdx);
				afterJumpNeedABlock = true;
			}
		}
	}

	@Override
	public void visitTryCatchBlock(Label start, Label end, Label handler, String type) {
		// TODO Auto-generated method stub
		super.visitTryCatchBlock(start, end, handler, type);
		if(Configuration.USE_FAV) {
			this.blockStartLables.add(start);
			this.blockStartLables.add(handler);
		}
	}

	@Override
	public void visitLabel(Label label) {
		// TODO Auto-generated method stub
		super.visitLabel(label);
		if(Configuration.USE_FAV) {
			if(afterJumpNeedABlock) {
				afterJumpNeedABlock = false;
				this.blockStartLables.add(label);
			}

			this.currentLabel = label;
			this.firstInsAfterCurLabel = false;
			curLabelIsABlock = false;
			for(Label l: this.blockStartLables) {
				if(l.equals(label)) {
			        this.blockIdx++;
			        curLabelIsABlock = true;
//					flagThisBlock(BlockType.LABEL.toString()+this.blockIdx);
					break;
				}
			}
		}
	}

	@Override
	public void visitFrame(int type, int numLocal, Object[] local, int numStack, Object[] stack) {
		// TODO Auto-generated method stub
		super.visitFrame(type, numLocal, local, numStack, stack);
		if(Configuration.USE_FAV) {
			if(curLabelIsABlock && !firstInsAfterCurLabel) {
				firstInsAfterCurLabel = true;
				flagThisBlock(BlockType.LABEL.toString()+this.blockIdx);
			}
		}
	}

	@Override
	public void visitInsn(int opcode) {
		// TODO Auto-generated method stub
		if(Configuration.USE_FAV) {
			if(afterJumpNeedABlock) {
				afterJumpNeedABlock = false;
				this.blockIdx++;
				flagThisBlock(BlockType.JUMP.toString()+this.blockIdx);
			}
			if(curLabelIsABlock && !firstInsAfterCurLabel) {
				firstInsAfterCurLabel = true;
				flagThisBlock(BlockType.LABEL.toString()+this.blockIdx);
			}
		}
		super.visitInsn(opcode);
	}

	@Override
	public void visitIntInsn(int opcode, int operand) {
		// TODO Auto-generated method stub
		if(Configuration.USE_FAV) {
			if(afterJumpNeedABlock) {
				afterJumpNeedABlock = false;
				this.blockIdx++;
				flagThisBlock(BlockType.JUMP.toString()+this.blockIdx);
			}
			if(curLabelIsABlock && !firstInsAfterCurLabel) {
				firstInsAfterCurLabel = true;
				flagThisBlock(BlockType.LABEL.toString()+this.blockIdx);
			}
		}
		super.visitIntInsn(opcode, operand);
	}

	@Override
    public void visitVarInsn(int opcode, int var) {
        // TODO Auto-generated method stub
        super.visitVarInsn(opcode, var);
    }

    @Override
    public void visitTypeInsn(int opcode, String type) {
        // TODO Auto-generated method stub
        super.visitTypeInsn(opcode, type);
    }

    @Override
    public void visitMultiANewArrayInsn(String descriptor, int numDimensions) {
        // TODO Auto-generated method stub
        super.visitMultiANewArrayInsn(descriptor, numDimensions);
    }

    @Override
	public void visitFieldInsn(int opcode, String owner, String name, String descriptor) {
		// TODO Auto-generated method stub
		if(Configuration.USE_FAV) {
			if(afterJumpNeedABlock) {
				afterJumpNeedABlock = false;
				this.blockIdx++;
				flagThisBlock(BlockType.JUMP.toString()+this.blockIdx);
			}
			if(curLabelIsABlock && !firstInsAfterCurLabel) {
				firstInsAfterCurLabel = true;
				flagThisBlock(BlockType.LABEL.toString()+this.blockIdx);
			}
		}
		super.visitFieldInsn(opcode, owner, name, descriptor);
	}

	@Override
	public void visitMethodInsn(int opcode, String owner, String name, String descriptor, boolean isInterface) {
		// TODO Auto-generated method stub
		if(Configuration.USE_FAV) {
			if(afterJumpNeedABlock) {
				afterJumpNeedABlock = false;
				this.blockIdx++;
				flagThisBlock(BlockType.JUMP.toString()+this.blockIdx);
			}
			if(curLabelIsABlock && !firstInsAfterCurLabel) {
				firstInsAfterCurLabel = true;
				flagThisBlock(BlockType.LABEL.toString()+this.blockIdx);
			}
		}
		super.visitMethodInsn(opcode, owner, name, descriptor, isInterface);
	}

	@Override
	public void visitInvokeDynamicInsn(String name, String descriptor, Handle bootstrapMethodHandle,
			Object... bootstrapMethodArguments) {
		// TODO Auto-generated method stub
		if(Configuration.USE_FAV) {
			if(afterJumpNeedABlock) {
				afterJumpNeedABlock = false;
				this.blockIdx++;
				flagThisBlock(BlockType.JUMP.toString()+this.blockIdx);
			}
			if(curLabelIsABlock && !firstInsAfterCurLabel) {
				firstInsAfterCurLabel = true;
				flagThisBlock(BlockType.LABEL.toString()+this.blockIdx);
			}
		}
		super.visitInvokeDynamicInsn(name, descriptor, bootstrapMethodHandle, bootstrapMethodArguments);
	}

	@Override
	public void visitLdcInsn(Object value) {
		// TODO Auto-generated method stub
		if(Configuration.USE_FAV) {
			if(afterJumpNeedABlock) {
				afterJumpNeedABlock = false;
				this.blockIdx++;
				flagThisBlock(BlockType.JUMP.toString()+this.blockIdx);
			}
			if(curLabelIsABlock && !firstInsAfterCurLabel) {
				firstInsAfterCurLabel = true;
				flagThisBlock(BlockType.LABEL.toString()+this.blockIdx);
			}
		}
		super.visitLdcInsn(value);
	}

	@Override
	public void visitIincInsn(int var, int increment) {
		// TODO Auto-generated method stub
		if(Configuration.USE_FAV) {
			if(afterJumpNeedABlock) {
				afterJumpNeedABlock = false;
				this.blockIdx++;
				flagThisBlock(BlockType.JUMP.toString()+this.blockIdx);
			}
			if(curLabelIsABlock && !firstInsAfterCurLabel) {
				firstInsAfterCurLabel = true;
				flagThisBlock(BlockType.LABEL.toString()+this.blockIdx);
			}
		}
		super.visitIincInsn(var, increment);
	}

	private void flagThisBlock(String block_suffix) {
		String blockString = this.className+"."+this.name+this.desc+"|"+block_suffix;
		int pos = CoverageMap.getBlockPos(blockString);
//		FrameNode fn = getCurrentFrameNode();
		super.visitLdcInsn(pos);
		super.visitMethodInsn(Opcodes.INVOKESTATIC, "java/crashfuzz/instrumenter/CodeCoverageMV",
				"markBlock", "(I)V", false);
//        acceptFn(fn);
	}
	public static void test() {
		return;
	}

	public static void markBlock(int blockPos) {
    	boolean marked = CoverageMap.getBit(blockPos);
    	if(marked) {
//    		System.out.println("CrashFuzz: this position was marked "+blockPos);
    		return;
    	}
//		System.out.println("CrashFuzz: mark "+blockPos);
//		CoverageMap.trace_map.setBit(blockPos, true);
		CoverageMap.setBit(blockPos, true);
    	CoverageMap.save_bit_map();
	}
}
