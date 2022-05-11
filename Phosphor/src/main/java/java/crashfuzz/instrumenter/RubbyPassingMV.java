package java.crashfuzz.instrumenter;

import edu.columbia.cs.psl.phosphor.Configuration;
import edu.columbia.cs.psl.phosphor.TaintUtils;
import edu.columbia.cs.psl.phosphor.control.ControlFlowPropagationPolicy;
import edu.columbia.cs.psl.phosphor.control.OpcodesUtil;
import edu.columbia.cs.psl.phosphor.instrumenter.TaintAdapter;
import edu.columbia.cs.psl.phosphor.instrumenter.analyzer.NeverNullArgAnalyzerAdapter;
import edu.columbia.cs.psl.phosphor.instrumenter.analyzer.ReferenceArrayTarget;
import edu.columbia.cs.psl.phosphor.struct.*;
import edu.columbia.cs.psl.phosphor.struct.harmony.util.LinkedList;
import edu.columbia.cs.psl.phosphor.struct.harmony.util.*;

import org.objectweb.asm.*;
import org.objectweb.asm.tree.MethodNode;

import static edu.columbia.cs.psl.phosphor.instrumenter.TaintMethodRecord.*;


public class RubbyPassingMV extends TaintAdapter implements Opcodes {

    static final String BYTE_NAME = "java/lang/Byte";
    static final String BOOLEAN_NAME = "java/lang/Boolean";
    static final String INTEGER_NAME = "java/lang/Integer";
    static final String FLOAT_NAME = "java/lang/Float";
    static final String LONG_NAME = "java/lang/Long";
    static final String CHARACTER_NAME = "java/lang/Character";
    static final String DOUBLE_NAME = "java/lang/Double";
    static final String SHORT_NAME = "java/lang/Short";
    private final int lastArg;
    private final Type[] paramTypes;
    private final Type originalMethodReturnType;
    private final Type newReturnType;
    private final String name;
    private final boolean isStatic;
    private final String owner;
    private final String descriptor;
    private final MethodVisitor passThroughMV;
    private final boolean rewriteLVDebug;
    private final boolean isLambda;
    private final boolean isObjOutputStream;
    private final ControlFlowPropagationPolicy controlFlowPolicy;
    private final List<MethodNode> wrapperMethodsToAdd;
    private final Set<Label> exceptionHandlers = new HashSet<>();
    ReferenceArrayTarget referenceArrayTarget;
    int line = 0;
    private boolean isIgnoreAllInstrumenting;
    private boolean isRawInstruction = false;
    private boolean isTaintlessArrayStore = false;
    private boolean doNotUnboxTaints;
    private boolean isAtStartOfExceptionHandler;

    private final String originalDesc;//crashfuzz

    public RubbyPassingMV(MethodVisitor mv, int access, String owner, String name, String descriptor, String signature,
                          String[] exceptions, String originalDesc, NeverNullArgAnalyzerAdapter analyzer,
                          MethodVisitor passThroughMV, LinkedList<MethodNode> wrapperMethodsToAdd,
                          ControlFlowPropagationPolicy controlFlowPolicy) {
        super(access, owner, name, descriptor, signature, exceptions, mv, analyzer);
        Configuration.taintTagFactory.instrumentationStarting(access, name, descriptor);
        this.isLambda = this.isIgnoreAllInstrumenting = owner.contains("$Lambda$");
        this.name = name;
        this.owner = owner;
        this.wrapperMethodsToAdd = wrapperMethodsToAdd;
        this.rewriteLVDebug = owner.equals("java/lang/invoke/MethodType");
        this.passThroughMV = passThroughMV;
        this.descriptor = descriptor;
        this.isStatic = (access & Opcodes.ACC_STATIC) != 0;
        this.isObjOutputStream = (owner.equals("java/io/ObjectOutputStream") && name.startsWith("writeObject0"))
                || (owner.equals("java/io/ObjectInputStream") && name.startsWith("defaultReadFields"));
        this.paramTypes = calculateParamTypes(isStatic, descriptor);
        this.lastArg = paramTypes.length - 1;
        this.originalMethodReturnType = Type.getReturnType(originalDesc);
        this.newReturnType = Type.getReturnType(descriptor);
        this.controlFlowPolicy = controlFlowPolicy;
        this.originalDesc = originalDesc;
    }

    @Override
    public void visitInsn(int opcode) {
        if(isLambda && OpcodesUtil.isReturnOpcode(opcode)) {
            visitLambdaReturn(opcode);
        } else if(opcode == TaintUtils.RAW_INSN) {
            isRawInstruction = !isRawInstruction;
        } else if(opcode == TaintUtils.IGNORE_EVERYTHING) {
            isIgnoreAllInstrumenting = !isIgnoreAllInstrumenting;
            Configuration.taintTagFactory.signalOp(opcode, null);
            super.visitInsn(opcode);
        } else if(opcode == TaintUtils.NO_TAINT_STORE_INSN) {
            isTaintlessArrayStore = true;
        } else if(isIgnoreAllInstrumenting || isRawInstruction || opcode == NOP || opcode == TaintUtils.FOLLOWED_BY_FRAME) {
            if(OpcodesUtil.isReturnOpcode(opcode) && this.newReturnType.getInternalName().equals(Type.getInternalName(TaintedReferenceWithObjTag.class))) {
            	NEW_EMPTY_TAINT.delegateVisit(mv);
                visitReturn(opcode);
            } else {
                super.visitInsn(opcode);
            }
            //crashfuzz: gy fix phosphor error
            // - super.visitInsn(opcode);
        } else if(OpcodesUtil.isReturnOpcode(opcode)) {
        	if(opcode != RETURN) {
        		NEW_EMPTY_TAINT.delegateVisit(mv);
        	}
            visitReturn(opcode);
        } else {
            super.visitInsn(opcode);
        }
    }

    /**
     * stack_pre = [value] or [] if opcode is RETURN
     * stack_post = []
     *
     * @param opcode the opcode of the instruction originally to be visited either RETURN, ARETURN, IRETURN, DRETURN,
     *               FRETURN, or LRETURN
     */
    private void visitLambdaReturn(int opcode) {
        // Do we need to box?
        if(newReturnType.getDescriptor().contains("edu/columbia/cs/psl/phosphor/struct")) {
            //Probably need to box...
            int returnHolder = lastArg - 1;
            super.visitVarInsn(ALOAD, returnHolder);
            if(opcode == LRETURN || opcode == DRETURN) {
                super.visitInsn(DUP_X2);
                super.visitInsn(POP);
            } else {
                super.visitInsn(SWAP);
            }
            String valDesc = opcode == ARETURN ? "Ljava/lang/Object;" : originalMethodReturnType.getDescriptor();
            super.visitFieldInsn(PUTFIELD, newReturnType.getInternalName(), "val", valDesc);
            super.visitVarInsn(ALOAD, returnHolder);
            super.visitInsn(DUP);
            NEW_EMPTY_TAINT.delegateVisit(mv);
            super.visitFieldInsn(PUTFIELD, newReturnType.getInternalName(), "taint", Configuration.TAINT_TAG_DESC);
            super.visitInsn(ARETURN);
        } else {
            super.visitInsn(opcode);
        }
    }

    /**
     * stack_pre = [value taint] or [] if opcode is RETURN
     * stack_post = []
     *
     * @param opcode the opcode of the instruction originally to be visited either RETURN, ARETURN, IRETURN, DRETURN,
     *               FRETURN, or LRETURN
     */
    private void visitReturn(int opcode) {
        controlFlowPolicy.onMethodExit(opcode);
        if(opcode == RETURN) {
            super.visitInsn(opcode);
            return;
        }
        int retIdx = lvs.getPreAllocatedReturnTypeVar(newReturnType);
        super.visitVarInsn(ALOAD, retIdx);
        super.visitInsn(SWAP);
        super.visitFieldInsn(PUTFIELD, newReturnType.getInternalName(), "taint", Configuration.TAINT_TAG_DESC);
        super.visitVarInsn(ALOAD, retIdx);
        if(opcode == DRETURN || opcode == LRETURN) {
            super.visitInsn(DUP_X2);
            super.visitInsn(POP);
        } else {
            super.visitInsn(SWAP);
        }
        String valDesc = opcode == ARETURN ? "Ljava/lang/Object;" : originalMethodReturnType.getDescriptor();
        super.visitFieldInsn(PUTFIELD, newReturnType.getInternalName(), "val", valDesc);
        super.visitVarInsn(ALOAD, retIdx);
        super.visitInsn(ARETURN);
    }

    public static Type[] calculateParamTypes(boolean isStatic, String descriptor) {
        Type[] newArgTypes = Type.getArgumentTypes(descriptor);
        int lastArg = isStatic ? 0 : 1; // If non-static, then arg[0] = this
        for(Type t : newArgTypes) {
            lastArg += t.getSize();
        }
        Type[] paramTypes = new Type[lastArg + 1];
        int n = (isStatic ? 0 : 1);
        for(Type newArgType : newArgTypes) {
            paramTypes[n] = newArgType;
            n += newArgType.getSize();
        }
        return paramTypes;
    }
}