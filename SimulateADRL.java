//Script simulate ADRL instruction combining ADRP and ADD and fix string reference issues
//@author Grzegorz Wypych (h0rac)
//@category Processor AARCH (ARM64 v8)
//@keybinding 
//@menupath 
//@toolbar 

import ghidra.app.script.GhidraScript;
import ghidra.program.model.symbol.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.scalar.Scalar;

public class SimulateADRL extends GhidraScript {

    public void run() throws Exception {
        adrlSimulate();
    }

    private void adrlSimulate() {
        Listing listing = currentProgram.getListing();
        monitor.initialize(listing.getNumCodeUnits());
        CodeUnitIterator i = listing.getCodeUnits(true);

        while (i.hasNext() && !monitor.isCancelled()) {
            CodeUnit temp = i.next();
            monitor.incrementProgress(1);

            if (temp.getMnemonicString().equals("adrp")) {
                Address adrpAddr = temp.getAddress();
                Address nextAddr = temp.getMaxAddress().add(1);
                CodeUnit codeUnit = currentProgram.getListing().getCodeUnitAt(nextAddr);

                if (codeUnit == null) {
                    continue;
                }

                String addOperand = codeUnit.getMnemonicString();
                Instruction instr = listing.getInstructionAt(adrpAddr);

                if (instr == null) {
                    continue;
                }

                long adrpValue = getOperandValue(instr, 1);

                if (addOperand.equals("add")) {
                    println("ADRP mnemonic address: " + adrpAddr);
                    instr = listing.getInstructionAt(nextAddr);

                    if (instr == null) {
                        continue;
                    }

                    long nextAddrValue = getOperandValue(instr, 2);
                    long refValue = adrpValue + nextAddrValue;
                    Address addr = parseAddress(Long.toHexString(refValue));

                    if (addr != null) {
                        temp.addOperandReference(1, addr, RefType.DATA, SourceType.DEFAULT);
                    }
                }
            }
        }
    }

    private long getOperandValue(Instruction instr, int operandIndex) {
        Object[] operands = instr.getOpObjects(operandIndex);

        if (operands != null && operands.length > 0) {
            Object operand = operands[0];

            if (operand instanceof Scalar) {
                return ((Scalar) operand).getValue();
            }
            else {
                println("Skipping non-immediate operand: " + operand);
            }
        }

        return 0;
    }
}