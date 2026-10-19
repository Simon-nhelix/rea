//@category REA Verification
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Program;

/** Assert decoded instructions and seed outcome in a real console import. */
public class ReaConsoleSeedOrderProbe extends GhidraScript {
    @Override public void run() throws Exception {
        int width = Integer.parseInt(getScriptArgs()[0]);
        var instruction = getInstructionAt(toAddr(0x018000));
        if (instruction == null || !instruction.getMnemonicString().equals("LDA") ||
                instruction.getLength() != width) {
            throw new IllegalStateException("console target instruction width: " + instruction);
        }
        var reset = getInstructionAt(toAddr(0x8000));
        if (reset == null || !reset.getMnemonicString().equals("JML") ||
                getFunctionAt(toAddr(0x8000)) == null) {
            throw new IllegalStateException("console reset decoding/function lost");
        }
        String report = currentProgram.getOptions(Program.PROGRAM_INFO)
            .getString("REA analysis seeds", null);
        if (width == 3 && (report == null || !report.contains("\"context_applied\":3") ||
                !report.contains("\"function_created\":1"))) {
            throw new IllegalStateException("explicit contexts/functions not committed: " + report);
        }
        if (width == 2 && report != null) {
            throw new IllegalStateException("unseeded import reported caller seeds");
        }
        println("REA_CONSOLE_SEED_ORDER_OK width=" + width);
    }
}
