//@category REA Verification
import java.math.BigInteger;
import ghidra.app.emulator.EmulatorHelper;
import java.io.ByteArrayInputStream;
import ghidra.app.util.headless.HeadlessScript;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.pcode.PcodeOp;

/** Real installed-SLA checks; no source-text assertions or target execution. */
public class Rea65816SemanticsProbe extends HeadlessScript {
    private int checks;
    private void require(boolean value, String message) {
        if (!value) throw new IllegalStateException(message);
        checks++;
    }
    private Instruction fixture(long offset, int e, int m, int x, byte[] bytes) throws Exception {
        var address = toAddr(offset);
        currentProgram.getMemory().createInitializedBlock("probe_" + Long.toHexString(offset), address,
            new ByteArrayInputStream(bytes), bytes.length, monitor, false);
        var context = currentProgram.getProgramContext();
        for (var pair : new String[][]{{"ctx_EF", ""+e},{"ctx_MF",""+m},{"ctx_XF",""+x},{"ctx_carry_known","0"}}) {
            var register = currentProgram.getRegister(pair[0]);
            require(register != null, "custom context " + pair[0]);
            context.setValue(register, address, address.add(bytes.length-1), new BigInteger(pair[1]));
        }
        disassemble(address);
        var instruction = getInstructionAt(address);
        require(instruction != null, "decoded fixture " + address);
        return instruction;
    }
    private int count(Instruction instruction, int opcode) {
        int count = 0;
        for (var op : instruction.getPcode()) if (op.getOpcode() == opcode) count++;
        return count;
    }
    @Override public void run() throws Exception {
        require(currentProgram.getLanguageID().toString().startsWith("65816:"), "65816 language");
        long at = 0x808000;
        while (currentProgram.getMemory().intersects(toAddr(at),toAddr(at+0x2000))) {
            at += 0x10000;
            require(at < 0xff0000,"free fixture bank");
        }
        for (int e : new int[]{0,1}) {
            var jsr = fixture(at, e, 1,1,new byte[]{0x20,0x34,0x12}); at+=0x100;
            require(count(jsr,PcodeOp.STORE)==2, "JSR pushes two bytes");
            require(count(jsr,PcodeOp.CALL)==1, "JSR direct call");
            var jsl = fixture(at,e,1,1,new byte[]{0x22,0x34,0x12,(byte)0x81}); at+=0x100;
            require(count(jsl,PcodeOp.STORE)==3,"JSL pushes bank and PC");
            for (int opcode : new int[]{0x60,0x6b,0x40}) {
                var ret=fixture(at,e,1,1,new byte[]{(byte)opcode});at+=0x100;
                int expected=opcode==0x60?2:opcode==0x6b?3:e==0?4:3;
                require(count(ret,PcodeOp.LOAD)==expected,"return restores stack bytes " + opcode + " E="+e);
                require(count(ret,PcodeOp.RETURN)==1,"return control flow " + opcode);
            }
        }
        for (int bits : new int[]{0,1}) {
            var load=fixture(at,0,bits,bits,bits==1?new byte[]{(byte)0xa9,0x34}:new byte[]{(byte)0xa9,0x34,0x12});at+=0x100;
            require(load.getLength()==(bits==1?2:3),"M-dependent LDA length");
        }
        var bra=fixture(at,0,1,1,new byte[]{(byte)0x80,(byte)0xfc});at+=0x100;
        require(bra.getFlows().length==1 && bra.getFlows()[0].getOffset()==bra.getAddress().getOffset()-2,"signed static branch destination");
        var indexed=fixture(at,0,1,1,new byte[]{(byte)0xfc,0x34,0x12});at+=0x100;
        require(count(indexed,PcodeOp.CALLIND)==1,"computed JSR destination");
        require(count(indexed,PcodeOp.STORE)==2,"computed JSR retains stack effects");
        for (int carry : new int[]{0,1}) {
            var setup=fixture(at,1,1,1,new byte[]{(byte)(carry==0?0x18:0x38),(byte)0xfb,(byte)0xa9,0x34});at+=0x100;
            var xce=getInstructionAt(setup.getAddress().add(1));
            require(xce!=null && xce.getMnemonicString().equals("XCE"),"known-carry XCE decode");
            var next=getInstructionAt(setup.getAddress().add(2));
            require(next!=null && next.getLength()==2,"XCE retains 8-bit accumulator when leaving emulation");
            var ef=currentProgram.getRegister("ctx_EF");
            require(currentProgram.getProgramContext().getValue(ef,next.getAddress(),false).intValue()==carry,"XCE propagated E");
        }
        var widths=fixture(at,0,1,1,new byte[]{(byte)0xc2,0x30,(byte)0xa9,0x34,0x12,(byte)0xe2,0x30,(byte)0xa9,0x56});
        require(getInstructionAt(widths.getAddress().add(2)).getLength()==3,"REP widens following immediate");
        require(getInstructionAt(widths.getAddress().add(7)).getLength()==2,"SEP narrows following immediate");
        at+=0x100;
        var push=fixture(at,0,0,0,new byte[]{0x48});at+=0x100;
        var emu=new EmulatorHelper(currentProgram);
        try {
            emu.setContextRegister(currentProgram.getProgramContext().getRegisterValue(currentProgram.getRegister("contextreg"),push.getAddress()));
            emu.writeRegister("PC_FULL",push.getAddress().getOffset());
            emu.writeRegister("SP",0);
            emu.writeRegister("C",0x1234);
            require(emu.step(monitor),"execute native PHA: " + emu.getLastError());
            require(emu.readRegister("SP").intValue()==0xfffe,"native stack wraps at 16 bits");
            require((emu.readMemoryByte(toAddr(0))&255)==0x12,"native push high at bank-zero zero");
            require((emu.readMemoryByte(toAddr(0xffff))&255)==0x34,"native push low at bank-zero FFFF");
        } finally { emu.dispose(); }
        var call=fixture(at,1,1,1,new byte[]{0x20,0x34,0x12});at+=0x100;
        emu=new EmulatorHelper(currentProgram);
        try {
            emu.setContextRegister(currentProgram.getProgramContext().getRegisterValue(currentProgram.getRegister("contextreg"),call.getAddress()));
            emu.writeRegister("PC_FULL",call.getAddress().getOffset());
            emu.writeRegister("SP",0x100);
            require(emu.step(monitor),"execute emulation JSR: " + emu.getLastError());
            require(emu.readRegister("SP").intValue()==0x1fe,"emulation stack remains in page one; actual="+emu.readRegister("SP").toString(16)+" context="+emu.getContextRegister());
            int ret=(int)(call.getAddress().getOffset()+2)&0xffff;
            require((emu.readMemoryByte(toAddr(0x100))&255)==(ret>>>8),"JSR pushed high return byte");
            require((emu.readMemoryByte(toAddr(0x1ff))&255)==(ret&255),"JSR pushed low return byte with wrapping");
            require(emu.getExecutionAddress().getOffset()==((call.getAddress().getOffset()&0xff0000)|0x1234),"JSR destination retains bank");
        } finally { emu.dispose(); }
        var php=fixture(at,0,1,1,new byte[]{0x08});at+=0x100;
        emu=new EmulatorHelper(currentProgram);
        try {
            emu.setContextRegister(currentProgram.getProgramContext().getRegisterValue(currentProgram.getRegister("contextreg"),php.getAddress()));
            emu.writeRegister("PC_FULL",php.getAddress().getOffset());emu.writeRegister("SP",0x1ff);
            emu.writeRegister("MF",1);emu.writeRegister("XF",1);emu.writeRegister("EF",0);
            for (String flag:new String[]{"NF","VF","DF","IF","ZF","CF"}) emu.writeRegister(flag,0);
            require(emu.step(monitor),"execute native PHP");
            require((emu.readMemoryByte(toAddr(0x1ff))&255)==0x30,"PHP stores runtime M/X flags; actual="+(emu.readMemoryByte(toAddr(0x1ff))&255));
        } finally { emu.dispose(); }
        var enter=fixture(at,0,0,0,new byte[]{0x38,(byte)0xfb});at+=0x100;
        emu=new EmulatorHelper(currentProgram);
        try {
            emu.setContextRegister(currentProgram.getProgramContext().getRegisterValue(currentProgram.getRegister("contextreg"),enter.getAddress()));
            emu.writeRegister("PC_FULL",enter.getAddress().getOffset());
            emu.writeRegister("EF",0);emu.writeRegister("MF",0);emu.writeRegister("XF",0);
            emu.writeRegister("SP",0x1234);emu.writeRegister("X",0xabcd);emu.writeRegister("Y",0xdef0);
            require(emu.step(monitor),"execute SEC");require(emu.step(monitor),"execute XCE");
            require(emu.readRegister("EF").intValue()==1 && emu.readRegister("CF").intValue()==0,"XCE exchanges old E and carry");
            require(emu.readRegister("MF").intValue()==1 && emu.readRegister("XF").intValue()==1,"emulation forces M/X");
            require(emu.readRegister("X").intValue()==0xcd && emu.readRegister("Y").intValue()==0xf0,"emulation clears index high bytes");
            require(emu.readRegister("SP").intValue()==0x134,"emulation forces stack page one");
        } finally { emu.dispose(); }
        var modes=fixture(at,0,1,1,new byte[]{(byte)0xc2,0x30,(byte)0xe2,0x30});at+=0x100;
        emu=new EmulatorHelper(currentProgram);
        try {
            emu.setContextRegister(currentProgram.getProgramContext().getRegisterValue(currentProgram.getRegister("contextreg"),modes.getAddress()));
            emu.writeRegister("PC_FULL",modes.getAddress().getOffset());
            for (String flag:new String[]{"NF","VF","DF","IF","ZF","CF"}) emu.writeRegister(flag,0);
            emu.writeRegister("EF",0);emu.writeRegister("MF",1);emu.writeRegister("XF",1);
            emu.writeRegister("X",0xabcd);emu.writeRegister("Y",0xdef0);
            require(emu.step(monitor),"execute REP");
            require(emu.readRegister("MF").intValue()==0 && emu.readRegister("XF").intValue()==0,"REP updates runtime widths");
            require(emu.step(monitor),"execute SEP");
            require(emu.readRegister("MF").intValue()==1 && emu.readRegister("XF").intValue()==1,"SEP updates runtime widths");
            require(emu.readRegister("X").intValue()==0xcd && emu.readRegister("Y").intValue()==0xf0,"SEP clears index high bytes");
        } finally { emu.dispose(); }
        println("REA_65816_SEMANTICS_OK checks="+checks);
    }
}
