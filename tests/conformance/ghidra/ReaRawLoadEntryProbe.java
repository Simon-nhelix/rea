//@category REA Verification
import ghidra.app.util.headless.HeadlessScript;
import ghidra.program.model.listing.Program;

/** Check an actual BinaryLoader import with distinct file base and entry. */
public class ReaRawLoadEntryProbe extends HeadlessScript {
    @Override public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 3) throw new IllegalArgumentException("load, entry, file length required");
        var space = currentProgram.getAddressFactory().getDefaultAddressSpace();
        var load = space.getAddress(args[0]);
        var entry = space.getAddress(args[1]);
        long length = Long.decode(args[2]);
        var block = currentProgram.getMemory().getBlock(load);
        if (block == null || !block.isInitialized() || !block.getStart().equals(load) ||
                block.getSize() != length || !block.getEnd().equals(load.add(length - 1))) {
            throw new IllegalStateException("source extent differs from declared raw load");
        }
        boolean sourceMapped = false;
        for (var source : block.getSourceInfos()) {
            if (source.getFileBytes().isPresent() && source.getFileBytesOffset() == 0 &&
                    source.getMinAddress().equals(load)) sourceMapped = true;
        }
        if (!sourceMapped || !currentProgram.getOptions(Program.PROGRAM_INFO)
                .getBoolean("REA raw binary prepared", false)) {
            throw new IllegalStateException("file offset zero was not prepared at the load address");
        }
        if (getFunctionAt(entry) == null || (!entry.equals(load) && getFunctionAt(load) != null)) {
            throw new IllegalStateException("actual entry must be seeded; load base must not be an invented function");
        }
        println("REA_RAW_LOAD_ENTRY_OK load=" + load + " entry=" + entry +
            " bytes=" + length + " entry_file_offset=" + entry.subtract(load));
    }
}
