//@category REA Verification
import java.io.ByteArrayInputStream;
import ghidra.app.util.headless.HeadlessScript;
import ghidra.app.emulator.EmulatorHelper;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.pcode.PcodeOp;

/** Tests installed SLA semantics on synthetic bytes; never executes a target. */
public class ReaGbPceSemanticsProbe extends HeadlessScript {
    private int checks;
    private void require(boolean condition, String message) {
        if (!condition) throw new IllegalStateException(message);
        checks++;
    }
    private Instruction fixture(long at, int... bytes) throws Exception {
        byte[] data = new byte[bytes.length];
        for (int i=0;i<bytes.length;i++) data[i]=(byte)bytes[i];
        currentProgram.getMemory().createInitializedBlock("fixture_"+Long.toHexString(at),toAddr(at),new ByteArrayInputStream(data),data.length,monitor,false);
        disassemble(toAddr(at));
        return getInstructionAt(toAddr(at));
    }
    private EmulatorHelper emulator(Instruction ins) {
        var emu=new EmulatorHelper(currentProgram);
        emu.writeRegister("PC",ins.getAddress().getOffset());
        return emu;
    }
    private void step(EmulatorHelper emu) throws Exception {
        require(emu.step(monitor),"pcode step: "+emu.getLastError());
    }
    private void put(EmulatorHelper emu,long at,int value) { emu.writeMemory(toAddr(at),new byte[]{(byte)value}); }
    private int reg(EmulatorHelper emu,String name) {return emu.readRegister(name).intValue();}
    private void gb() throws Exception {
        var stop=fixture(0x4000,0x10,0x00,0x00);
        require(stop!=null && stop.getLength()==2,"STOP consumes padding byte");
        require(stop.getPcode().length>0 && stop.getPcode()[0].getOpcode()==PcodeOp.CALLOTHER,"STOP has explicit hardware userop");
        require(fixture(0x4100,0xe3)==null,"Z80 EX (SP),HL is invalid on SM83");
        var swap=fixture(0x4200,0xcb,0x30);
        require(swap!=null && swap.getMnemonicString().equals("SWAP"),"CB30 selects SM83 SWAP");
        var emu=emulator(swap);
        try {emu.writeRegister("B",0xa5);emu.writeRegister("F",0xf0);step(emu);require(reg(emu,"B")==0x5a && reg(emu,"F")==0,"SWAP value and flags");} finally {emu.dispose();}
        var pop=fixture(0x4300,0xf1);
        emu=emulator(pop);
        try {emu.writeRegister("SP",0x8000);put(emu,0x8000,0xff);put(emu,0x8001,0x12);step(emu);require(reg(emu,"AF")==0x12f0,"POP AF hardwires low F nibble");require(reg(emu,"SP")==0x8002,"POP advances SP");} finally {emu.dispose();}
        for(int op:new int[]{0xe8,0xf8}) {
            var add=fixture(op==0xe8?0x4400:0x4500,op,1);
            emu=emulator(add);
            try {emu.writeRegister("SP",0xff);emu.writeRegister("F",0xc0);step(emu);require(reg(emu,op==0xe8?"SP":"HL")==0x100,"SP+1 arithmetic "+op);require(reg(emu,"F")==0x30,"SP+1 H/C set; Z/N clear "+op);} finally {emu.dispose();}
            var neg=fixture(op==0xe8?0x4600:0x4700,op,0xff);
            emu=emulator(neg);
            try {emu.writeRegister("SP",0);emu.writeRegister("F",0xf0);step(emu);require(reg(emu,op==0xe8?"SP":"HL")==0xffff,"SP signed negative displacement "+op);require(reg(emu,"F")==0,"negative displacement flags "+op);} finally {emu.dispose();}
        }
    }
    private void pce() throws Exception {
        var load=fixture(0xe000,0xa5,0xff);
        var emu=emulator(load);
        try {put(emu,0x20ff,0x7a);step(emu);require(reg(emu,"A")==0x7a,"ordinary zero page is $2000");} finally {emu.dispose();}
        var indexed=fixture(0xe080,0xb5,0xff);
        emu=emulator(indexed);
        try {emu.writeRegister("X",1);put(emu,0x2000,0x7a);step(emu);require(reg(emu,"A")==0x7a,"ordinary indexed zero page wraps");} finally {emu.dispose();}
        var indirect=fixture(0xe100,0xb1,0xff);
        emu=emulator(indirect);
        try {emu.writeRegister("Y",1);put(emu,0x20ff,0xff);put(emu,0x2000,0x12);put(emu,0x1300,0x7a);step(emu);require(reg(emu,"A")==0x7a,"zero page pointer high byte wraps within $2000");} finally {emu.dispose();}
        for (int op:new int[]{0xa3,0xb3}) {
            var tst=op==0xa3?fixture(0xe200,op,0xf0,0xff):fixture(0xe300,op,0xf0,0xff,0xff);
            emu=emulator(tst);
            try {emu.writeRegister("X",1);put(emu,op==0xa3?0x2000:0,0xc0);step(emu);require(reg(emu,"N")==1 && reg(emu,"V")==1 && reg(emu,"Z")==0,"indexed TST address/wrap/N/V/Z "+op);} finally {emu.dispose();}
        }
        var clearTst=fixture(0xe380,0xa3,0xc0,0xff);
        emu=emulator(clearTst);
        try {emu.writeRegister("X",1);put(emu,0x2000,0x3f);step(emu);require(reg(emu,"N")==0 && reg(emu,"V")==0 && reg(emu,"Z")==1,"TST clears N/V and sets Z for masked zero");} finally {emu.dispose();}
        var call=fixture(0xe400,0x20,0x00,0xe8);
        fixture(0xe800,0x60);
        emu=emulator(call);
        try {emu.writeRegister("SP",0x2100);step(emu);require(reg(emu,"SP")==0x21fe,"JSR per-byte stack wrapping");require((emu.readMemoryByte(toAddr(0x2100))&255)==0xe4 && (emu.readMemoryByte(toAddr(0x21ff))&255)==2,"JSR saves last operand address");require(emu.getExecutionAddress().getOffset()==0xe800,"JSR target");step(emu);require(reg(emu,"SP")==0x2100 && emu.getExecutionAddress().getOffset()==0xe403,"RTS wraps stack and restores next PC");} finally {emu.dispose();}
        var set=fixture(0xe500,0xf4);
        require(set!=null && set.getPcode().length>0 && set.getPcode()[0].getOpcode()==PcodeOp.CALLOTHER,"experimental SET exposes opaque effect");
    }
    @Override public void run() throws Exception {
        String id=currentProgram.getLanguageID().toString();
        if(id.equals("SM83:LE:16:default")) gb();
        else if(id.equals("HuC6280:LE:16:experimental")) pce();
        else throw new IllegalStateException("unexpected language "+id);
        println("REA_GB_PCE_SEMANTICS_OK language="+id+" checks="+checks);
    }
}
