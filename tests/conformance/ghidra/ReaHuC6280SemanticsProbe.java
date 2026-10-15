//@category REA Verification
import java.io.ByteArrayInputStream;
import ghidra.app.util.headless.HeadlessScript;
import ghidra.app.emulator.EmulatorHelper;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.pcode.PcodeOp;

/** Installed-SLA regression checks against Hudson manuals and independent arithmetic oracles.
 * Synthetic pcode only: no target executable or game is run. */
public class ReaHuC6280SemanticsProbe extends HeadlessScript {
 private int checks;
 private long cursor=0xa000;
 private void require(boolean condition,String message) {
  if(!condition) throw new IllegalStateException(message);
  checks++;
 }
 private Instruction at(long address,int... bytes) throws Exception {
  byte[] data=new byte[bytes.length];for(int i=0;i<bytes.length;i++)data[i]=(byte)bytes[i];
  currentProgram.getMemory().createInitializedBlock("probe_"+Long.toHexString(address),toAddr(address),new ByteArrayInputStream(data),data.length,monitor,false);
  disassemble(toAddr(address));
  return getInstructionAt(toAddr(address));
 }
 private Instruction fixture(int... bytes) throws Exception {long p=cursor;cursor+=16;return at(p,bytes);}
 private EmulatorHelper emulator(Instruction instruction) {
  var emu=new EmulatorHelper(currentProgram);
  for(String name:new String[]{"A","X","Y","N","V","B","D","I","Z","C","T"})emu.writeRegister(name,0);
  emu.writeRegister("SP",0x21ff);
  var gaps=new ghidra.program.model.address.AddressSet(toAddr(0),toAddr(0xffff));
  gaps.delete(currentProgram.getMemory().getLoadedAndInitializedAddressSet());
  for(var range:gaps.getAddressRanges())emu.writeMemory(range.getMinAddress(),new byte[(int)range.getLength()]);
  pc(emu,instruction);return emu;
 }
 private void pc(EmulatorHelper emu,Instruction instruction){emu.writeRegister("PC",instruction.getAddress().getOffset());}
 private int reg(EmulatorHelper emu,String name){return emu.readRegister(name).intValue();}
 private void put(EmulatorHelper emu,long address,int value){emu.writeMemory(toAddr(address),new byte[]{(byte)value});}
 private int get(EmulatorHelper emu,long address){return emu.readMemoryByte(toAddr(address))&255;}
 private void step(EmulatorHelper emu) throws Exception {require(emu.step(monitor),"pcode step: "+emu.getLastError());}
 // Literal producer golden derived from Mesen's 256-entry opcode/address-mode tables.
 private void catalog() throws Exception {
  String[] names=new String[]{
   "BRK","ORA","SXY","ST0","TSB","ORA","ASL","RMB","PHP","ORA","ASL","NOP","TSB","ORA","ASL","BBR",
   "BPL","ORA","ORA","ST1","TRB","ORA","ASL","RMB","CLC","ORA","INC","NOP","TRB","ORA","ASL","BBR",
   "JSR","AND","SAX","ST2","BIT","AND","ROL","RMB","PLP","AND","ROL","NOP","BIT","AND","ROL","BBR",
   "BMI","AND","AND","NOP","BIT","AND","ROL","RMB","SEC","AND","DEC","NOP","BIT","AND","ROL","BBR",
   "RTI","EOR","SAY","TMA","BSR","EOR","LSR","RMB","PHA","EOR","LSR","NOP","JMP","EOR","LSR","BBR",
   "BVC","EOR","EOR","TAM","CSL","EOR","LSR","RMB","CLI","EOR","PHY","NOP","NOP","EOR","LSR","BBR",
   "RTS","ADC","CLA","NOP","STZ","ADC","ROR","RMB","PLA","ADC","ROR","NOP","JMP","ADC","ROR","BBR",
   "BVS","ADC","ADC","TII","STZ","ADC","ROR","RMB","SEI","ADC","PLY","NOP","JMP","ADC","ROR","BBR",
   "BRA","STA","CLX","TST","STY","STA","STX","SMB","DEY","BIT","TXA","NOP","STY","STA","STX","BBS",
   "BCC","STA","STA","TST","STY","STA","STX","SMB","TYA","STA","TXS","NOP","STZ","STA","STZ","BBS",
   "LDY","LDA","LDX","TST","LDY","LDA","LDX","SMB","TAY","LDA","TAX","NOP","LDY","LDA","LDX","BBS",
   "BCS","LDA","LDA","TST","LDY","LDA","LDX","SMB","CLV","LDA","TSX","NOP","LDY","LDA","LDX","BBS",
   "CPY","CMP","CLY","TDD","CPY","CMP","DEC","SMB","INY","CMP","DEX","NOP","CPY","CMP","DEC","BBS",
   "BNE","CMP","CMP","TIN","CSH","CMP","DEC","SMB","CLD","CMP","PHX","NOP","NOP","CMP","DEC","BBS",
   "CPX","SBC","NOP","TIA","CPX","SBC","INC","SMB","INX","SBC","NOP","NOP","CPX","SBC","INC","BBS",
   "BEQ","SBC","SBC","TAI","SET","SBC","INC","SMB","SED","SBC","PLX","NOP","NOP","SBC","INC","BBS"
  };
  int[] sizes=new int[]{
   1,2,1,2,2,2,2,2,1,2,1,1,3,3,3,3,
   2,2,2,2,2,2,2,2,1,3,1,1,3,3,3,3,
   3,2,1,2,2,2,2,2,1,2,1,1,3,3,3,3,
   2,2,2,1,2,2,2,2,1,3,1,1,3,3,3,3,
   1,2,1,2,2,2,2,2,1,2,1,1,3,3,3,3,
   2,2,2,2,1,2,2,2,1,3,1,1,1,3,3,3,
   1,2,1,1,2,2,2,2,1,2,1,1,3,3,3,3,
   2,2,2,7,2,2,2,2,1,3,1,1,3,3,3,3,
   2,2,1,3,2,2,2,2,1,2,1,1,3,3,3,3,
   2,2,2,4,2,2,2,2,1,3,1,1,3,3,3,3,
   2,2,2,3,2,2,2,2,1,2,1,1,3,3,3,3,
   2,2,2,4,2,2,2,2,1,3,1,1,3,3,3,3,
   2,2,1,7,2,2,2,2,1,2,1,1,3,3,3,3,
   2,2,2,7,1,2,2,2,1,3,1,1,1,3,3,3,
   2,2,1,7,2,2,2,2,1,2,1,1,3,3,3,3,
   2,2,2,7,1,2,2,2,1,3,1,1,1,3,3,3
  };
  for(int op=0;op<256;op++){
   var instruction=at(0x8000+op*16,op,0x11,0x22,0x33,0x44,0x55,0x66);
   require(instruction!=null,"opcode decoded "+Integer.toHexString(op));
   require(instruction.getMnemonicString().equals(names[op]),"opcode mnemonic "+Integer.toHexString(op)+" actual="+instruction.getMnemonicString()+" expected="+names[op]);
   require(instruction.getLength()==sizes[op],"opcode length "+Integer.toHexString(op)+" actual="+instruction.getLength()+" expected="+sizes[op]);
  }
 }
 private int memoryReads(Instruction instruction){
  int count=0;
  for(var op:instruction.getPcode()){
   if(op.getOpcode()==PcodeOp.LOAD)count++;
   // A constant absolute address can be a direct memory varnode rather than LOAD.
   for(var input:op.getInputs())if(input.getAddress().getAddressSpace().isMemorySpace())count++;
  }
  return count;
 }
 private int memoryWrites(Instruction instruction){
  int count=0;
  for(var op:instruction.getPcode()){
   if(op.getOpcode()==PcodeOp.STORE)count++;
   if(op.getOutput()!=null && op.getOutput().getAddress().getAddressSpace().isMemorySpace())count++;
  }
  return count;
 }
 private void singleReadModifyWrite() throws Exception {
  // Decoder output must preserve one memory read, independently of final flags.
  // Repeated reads could observe different device values even when RAM tests pass.
  for(int opcode:new int[]{0x06,0x46,0x26,0x66,0xe6,0xc6}){
   var instruction=fixture(opcode,0x20);
   require(memoryReads(instruction)==1,"RMW has one operand load opcode="+opcode);
   require(memoryWrites(instruction)==1,"RMW has one operand store opcode="+opcode);
  }
 }
 private int decimal(int bcd){return (bcd>>4)*10+(bcd&15);}
 private int bcd(int decimal){int n=(decimal%100+100)%100;return (n/10)*16+n%10;}
 private void arithmetic() throws Exception {
  int[] binary={0,1,9,0x10,0x7f,0x80,0x99,0xfe,0xff};
  int[] decimals={0,1,9,0x10,0x19,0x49,0x50,0x90,0x99};
  for(int opcode:new int[]{0x69,0xe9}) for(int d=0;d<2;d++) {
   int[] values=d==0?binary:decimals;
   for(int rhs:values){var instruction=fixture(opcode,rhs);var emu=emulator(instruction);
    try {for(int lhs:values)for(int carry=0;carry<2;carry++){
     pc(emu,instruction);emu.writeRegister("A",lhs);emu.writeRegister("C",carry);emu.writeRegister("D",d);emu.writeRegister("V",1);emu.writeRegister("T",0);
     step(emu);
     int sum=opcode==0x69?lhs+rhs+carry:lhs-rhs-(1-carry);
     int expected=sum&255;
     int expectedC=opcode==0x69?(sum>255?1:0):(sum>=0?1:0);
     int expectedV=opcode==0x69?((~(lhs^rhs)&(lhs^expected)&128)!=0?1:0):(((lhs^rhs)&(lhs^expected)&128)!=0?1:0);
     if(d==1){int result=opcode==0x69?decimal(lhs)+decimal(rhs)+carry:decimal(lhs)-decimal(rhs)-(1-carry);expected=bcd(result);expectedC=opcode==0x69?(result>=100?1:0):(result>=0?1:0);expectedV=1;}
     // ADC T redirection is tested separately; here force accumulator behavior.
     require(reg(emu,"A")==expected,"arithmetic result op="+opcode+" D="+d+" lhs="+lhs+" rhs="+rhs+" C="+carry+" actual="+reg(emu,"A")+" expected="+expected);
     require(reg(emu,"C")==expectedC && reg(emu,"V")==expectedV,"arithmetic C/V op="+opcode+" D="+d+" lhs="+lhs+" rhs="+rhs+" C="+carry);
     require(reg(emu,"N")==((expected>>7)&1) && reg(emu,"Z")== (expected==0?1:0),"arithmetic N/Z");
     require(reg(emu,"T")==0,"arithmetic consumes T");
    }}finally{emu.dispose();}
   }
  }
 }
 private void memoryMode() throws Exception {
  for(int opcode:new int[]{0x09,0x29,0x49,0x69,0x12,0x32,0x52,0x72}){
   var set=fixture(0xf4,opcode,opcode>=0x10 && (opcode&15)==2?0x40:0x81);
   var emu=emulator(set);
   try {emu.writeRegister("A",0x55);emu.writeRegister("X",0x10);emu.writeRegister("C",1);emu.writeRegister("V",1);emu.writeRegister("D",0);put(emu,0x2010,0x7f);put(emu,0x2040,0);put(emu,0x2041,0x30);put(emu,0x3000,0x81);
    step(emu);require(reg(emu,"T")==1,"SET sets runtime T");step(emu);
    int family=opcode>>5;int expected=family==0?0xff:family==1?1:family==2?0xfe:1;
    require(reg(emu,"A")==0x55 && get(emu,0x2010)==expected,"T redirects only destination, opcode="+opcode);
    require(reg(emu,"N")==((expected>>7)&1) && reg(emu,"Z")==0 && reg(emu,"T")==0,"T ALU N/Z/consumption");
    require(reg(emu,"C")==1 && reg(emu,"V")== (family==3?0:1),"T ALU carry/overflow");
   } finally{emu.dispose();}
  }
  var sequence=fixture(0xf4,0xea,0x69,1);var emu=emulator(sequence);
  try{emu.writeRegister("A",0x55);emu.writeRegister("C",0);emu.writeRegister("D",0);step(emu);step(emu);require(reg(emu,"T")==0,"intervening NOP consumes SET");step(emu);require(reg(emu,"A")==0x56,"ADC after intervening NOP uses A");}finally{emu.dispose();}
  var sbc=fixture(0xf4,0xe9,1);emu=emulator(sbc);
  try{emu.writeRegister("A",0x55);emu.writeRegister("X",0x10);emu.writeRegister("C",1);emu.writeRegister("D",0);put(emu,0x2010,0x7f);step(emu);step(emu);require(reg(emu,"A")==0x54 && get(emu,0x2010)==0x7f && reg(emu,"T")==0,"SET SBC follows Hudson manual, not MAME T-SBC");}finally{emu.dispose();}
  var php=fixture(0xf4,0x08);emu=emulator(php);
  try{emu.writeRegister("SP",0x21ff);step(emu);step(emu);require((get(emu,0x21ff)&0x30)==0x10,"PHP stores B=1,T=0 after SET");}finally{emu.dispose();}
  var plp=fixture(0x28,0x29,0xff);emu=emulator(plp);
  try{emu.writeRegister("SP",0x21fe);emu.writeRegister("A",0x55);emu.writeRegister("X",0x10);put(emu,0x21ff,0x20);put(emu,0x2010,0x81);step(emu);require(reg(emu,"T")==1,"PLP restores T");step(emu);require(reg(emu,"A")==0x55 && get(emu,0x2010)==0x81 && reg(emu,"T")==0,"restored T redirects next AND");}finally{emu.dispose();}
 }
 private void indirectAndStatus() throws Exception {
  var jump=fixture(0x6c,0xff,0xff);var emu=emulator(jump);
  try{put(emu,0xffff,0x34);put(emu,0,0x12);step(emu);require(emu.getExecutionAddress().getOffset()==0x1234,"JMP indirect pointer wraps at FFFF");}finally{emu.dispose();}
  var indexed=fixture(0x7c,0xfe,0xff);emu=emulator(indexed);
  try{emu.writeRegister("X",1);put(emu,0xffff,0x34);put(emu,0,0x12);step(emu);require(emu.getExecutionAddress().getOffset()==0x1234,"JMP indexed indirect pointer wraps at FFFF");}finally{emu.dispose();}
  var target=fixture(0x29,0xff);var rti=fixture(0x40);emu=emulator(rti);
  try{emu.writeRegister("SP",0x21fc);emu.writeRegister("X",0x10);emu.writeRegister("A",0x55);put(emu,0x21fd,0x20);put(emu,0x21fe,(int)target.getAddress().getOffset()&255);put(emu,0x21ff,(int)target.getAddress().getOffset()>>8);put(emu,0x2010,0x81);step(emu);require(reg(emu,"T")==1 && emu.getExecutionAddress().equals(target.getAddress()),"RTI restores T and exact PC");step(emu);require(reg(emu,"A")==0x55 && get(emu,0x2010)==0x81 && reg(emu,"T")==0,"RTI-restored T affects next ALU");}finally{emu.dispose();}
 }
 private void bitAndClear() throws Exception {
  for(int opcode:new int[]{0x89,0x24,0x34,0x2c,0x3c}){
   var instruction=(opcode==0x89)?fixture(opcode,0xc0):(opcode==0x2c||opcode==0x3c)?fixture(opcode,0,0x30):fixture(opcode,0x20);
   require(memoryReads(instruction)==(opcode==0x89?0:1),"BIT uses a single captured operand opcode="+opcode+" reads="+memoryReads(instruction));
   var emu=emulator(instruction);
   try{emu.writeRegister("X",0);emu.writeRegister("A",0x0f);emu.writeRegister("T",1);put(emu,0x2020,0xc0);put(emu,0x3000,0xc0);step(emu);require(reg(emu,"N")==1 && reg(emu,"V")==1 && reg(emu,"Z")==1 && reg(emu,"T")==0,"BIT flags incl immediate "+opcode);}finally{emu.dispose();}
  }
  for(int opcode:new int[]{0x04,0x0c,0x14,0x1c}){
   var instruction=(opcode==0x0c||opcode==0x1c)?fixture(opcode,0,0x30):fixture(opcode,0x20);var emu=emulator(instruction);
   try{emu.writeRegister("A",0xc0);put(emu,0x2020,0xc0);put(emu,0x3000,0xc0);step(emu);boolean reset=opcode==0x14||opcode==0x1c;require(get(emu,opcode==0x0c||opcode==0x1c?0x3000:0x2020)==(reset?0:0xc0),"TRB/TSB memory");require(reg(emu,"N")==1 && reg(emu,"V")==1 && reg(emu,"Z")== (reset?1:0),"TRB/TSB pre-write N/V and post-write Z");}finally{emu.dispose();}
  }
  for(int opcode:new int[]{0x62,0x82,0xc2}){var instruction=fixture(opcode);var emu=emulator(instruction);try{emu.writeRegister("A",0x55);emu.writeRegister("X",0x66);emu.writeRegister("Y",0x77);for(String flag:new String[]{"N","V","Z","C","T"})emu.writeRegister(flag,1);step(emu);require(reg(emu,opcode==0x62?"A":opcode==0x82?"X":"Y")==0,"clear register");require(reg(emu,"N")==1 && reg(emu,"V")==1 && reg(emu,"Z")==1 && reg(emu,"C")==1 && reg(emu,"T")==0,"clear preserves arithmetic flags, consumes T");}finally{emu.dispose();}}
 }
 private void transfers() throws Exception {
  for(int opcode:new int[]{0x73,0xc3,0xd3,0xe3,0xf3}){
   int source=opcode==0xc3?0x3003:0x3000,destination=opcode==0xc3?0x3103:0x3100;
   var instruction=fixture(opcode,source&255,source>>8,destination&255,destination>>8,4,0);var emu=emulator(instruction);
   try{emu.writeRegister("SP",0x2100);emu.writeRegister("A",0x34);emu.writeRegister("X",0x56);emu.writeRegister("Y",0x12);for(String flag:new String[]{"N","V","Z","C","D","I","T"})emu.writeRegister(flag,1);for(int i=0;i<4;i++)put(emu,0x3000+i,(i+1)*0x11);step(emu);
    int[] expected=opcode==0xd3?new int[]{0x44}:opcode==0xe3?new int[]{0x33,0x44}:opcode==0xf3?new int[]{0x11,0x22,0x11,0x22}:new int[]{0x11,0x22,0x33,0x44};
    for(int i=0;i<expected.length;i++)require(get(emu,0x3100+i)==expected[i],"transfer direction/alternation "+opcode+" index="+i);
    require(reg(emu,"A")==0x34 && reg(emu,"X")==0x56 && reg(emu,"Y")==0x12 && reg(emu,"SP")==0x2100,"transfer saves/restores wrapped stack registers");
    for(String flag:new String[]{"N","V","Z","C","D","I"})require(reg(emu,flag)==1,"transfer preserves "+flag);
    require(reg(emu,"T")==0,"transfer consumes T");
   }finally{emu.dispose();}
  }
  var overlap=fixture(0x73,0,0x30,1,0x30,0xff,0);var emu=emulator(overlap);
  try{emu.writeRegister("SP",0x21ff);for(int i=0;i<256;i++)put(emu,0x3000+i,i==0?0:0xcc);step(emu);for(int i=0;i<256;i++)require(get(emu,0x3000+i)==0,"TII sequential overlap propagation index="+i);}finally{emu.dispose();}
  var wrap=fixture(0x73,0xff,0xff,0,0x31,2,0);emu=emulator(wrap);
  try{emu.writeRegister("SP",0x21ff);put(emu,0xffff,0xaa);put(emu,0,0xbb);step(emu);require(get(emu,0x3100)==0xaa && get(emu,0x3101)==0xbb,"transfer source wraps logical address");}finally{emu.dispose();}
  var zero=fixture(0xd3,0,0x30,0,0x31,0,0);emu=emulator(zero);
  try{emu.writeRegister("SP",0x21ff);put(emu,0x2fff,0x5a);put(emu,0x2ffe,0x6b);step(emu);require(get(emu,0x3100)==0x5a,"zero-length TIN copies65536 logical bytes");}finally{emu.dispose();}
 }

 private int status(EmulatorHelper emu){int p=0;String[] names={"C","Z","I","D","B","T","V","N"};for(int i=0;i<8;i++)p|=(reg(emu,names[i])&1)<<i;return p;}
 private int number(String hex){return Integer.parseInt(hex,16);}
 private void runtimeGolden() throws Exception {
  // Independent romlab/Mesen observations of the self-authored pce-fixture.mjs,
  // 2026-10-15. Each row retains input bytes/registers and observed output,
  // including all 32 RAM bytes; no value is calculated from this SLA.
  String[] rows=new String[]{
   "t-adc|e100|f46900|2|55|10|0|1|7f|e103|ff|55|10|0|c0|8000000000000000000000000000000000000000000000000000000000000000",
   "t-and|e120|f4290f|2|55|10|0|0|f0|e123|ff|55|10|0|2|0000000000000000000000000000000000000000000000000000000000000000",
   "t-eor|e140|f449ff|2|55|10|0|0|80|e143|ff|55|10|0|0|7f00000000000000000000000000000000000000000000000000000000000000",
   "t-ora|e160|f40980|2|55|10|0|0|01|e163|ff|55|10|0|80|8100000000000000000000000000000000000000000000000000000000000000",
   "t-sbc|e180|f4e901|2|55|10|0|1|80|e183|ff|54|10|0|1|8000000000000000000000000000000000000000000000000000000000000000",
   "t-consumed|e1a0|f4ea6901|3|55|10|0|0|7f|e1a4|ff|56|10|0|0|7f00000000000000000000000000000000000000000000000000000000000000",
   "decimal-adc|e1c0|6900|1|99|10|0|49||e1c2|ff|0|10|0|4b|0000000000000000000000000000000000000000000000000000000000000000",
   "decimal-sbc|e1e0|e901|1|0|10|0|49||e1e2|ff|99|10|0|c8|0000000000000000000000000000000000000000000000000000000000000000",
   "trb|e200|1410|1|c0|10|0|0|c0|e202|ff|c0|10|0|c2|0000000000000000000000000000000000000000000000000000000000000000",
   "tsb|e220|0410|1|80|10|0|0|00|e222|ff|80|10|0|0|8000000000000000000000000000000000000000000000000000000000000000",
   "bit-immediate|e240|8900|1|ff|10|0|c0||e242|ff|ff|10|0|2|0000000000000000000000000000000000000000000000000000000000000000",
   "cla|e260|62|1|ff|10|0|c1||e261|ff|0|10|0|c1|0000000000000000000000000000000000000000000000000000000000000000",
   "tii-overlap|e280|73102011200300|1|0|10|0|0|11223344|e287|ff|0|10|0|0|1111111100000000000000000000000000000000000000000000000000000000",
   "tdd|e2a0|c3132023200300|1|0|10|0|0|11223344|e2a7|ff|0|10|0|0|1122334400000000000000000000000000223344000000000000000000000000",
   "tin|e2c0|d3102020200300|1|0|10|0|0|11223344|e2c7|ff|0|10|0|0|1122334400000000000000000000000033000000000000000000000000000000",
   "tia|e2e0|e3102020200300|1|0|10|0|0|11223344|e2e7|ff|0|10|0|0|1122334400000000000000000000000033220000000000000000000000000000",
   "tai|e300|f3102020200300|1|0|10|0|0|11223344|e307|ff|0|10|0|0|1122334400000000000000000000000011221100000000000000000000000000"
  };
  for(String row:rows){String[] f=row.split("\\|",-1);byte[] code=java.util.HexFormat.of().parseHex(f[2]);int[] bytes=new int[code.length];for(int i=0;i<code.length;i++)bytes[i]=code[i]&255;
   var instruction=at(number(f[1]),bytes);var emu=emulator(instruction);
   try{emu.writeRegister("A",number(f[4]));emu.writeRegister("X",number(f[5]));emu.writeRegister("Y",number(f[6]));int initial=number(f[7]);String[] flags={"C","Z","I","D","B","T","V","N"};for(int i=0;i<8;i++)emu.writeRegister(flags[i],(initial>>i)&1);
    byte[] input=java.util.HexFormat.of().parseHex(f[8]);emu.writeMemory(toAddr(0x2010),new byte[32]);emu.writeMemory(toAddr(0x2010),input);
    for(int i=0;i<Integer.parseInt(f[3]);i++)step(emu);
    require(emu.getExecutionAddress().getOffset()==number(f[9]),f[0]+" runtime PC");
    require((reg(emu,"SP")&255)==number(f[10]),f[0]+" runtime SP");
    require(reg(emu,"A")==number(f[11]) && reg(emu,"X")==number(f[12]) && reg(emu,"Y")==number(f[13]),f[0]+" runtime A/X/Y");
    require(status(emu)==number(f[14]),f[0]+" runtime status actual="+Integer.toHexString(status(emu))+" expected="+f[14]);
    byte[] expected=java.util.HexFormat.of().parseHex(f[15]);for(int i=0;i<expected.length;i++)require(get(emu,0x2010+i)==(expected[i]&255),f[0]+" runtime RAM byte"+i);
    println("REA_HUC6280_RUNTIME_MATCH id="+f[0]+" status="+Integer.toHexString(status(emu)));
   }finally{emu.dispose();}
  }
 }

 @Override public void run() throws Exception {
  require(currentProgram.getLanguageID().toString().equals("HuC6280:LE:16:experimental"),"dedicated language");
  catalog();singleReadModifyWrite();arithmetic();memoryMode();bitAndClear();indirectAndStatus();transfers();runtimeGolden();
  println("REA_HUC6280_SEMANTICS_OK checks="+checks);
 }
}
