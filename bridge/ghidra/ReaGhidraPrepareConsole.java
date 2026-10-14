import ghidra.app.script.GhidraScript;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryBlockSourceInfo;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * Prepare console ROM / executable memory mappings, hardware RAM/MMIO regions,
 * and entry point before default Ghidra auto-analysis.
 */
public final class ReaGhidraPrepareConsole extends GhidraScript {
    private record FileMapSpec(
        String name,
        long address,
        long fileOffset,
        long byteLength,
        boolean readable,
        boolean writable,
        boolean executable
    ) {}

    private record MemoryRegionSpec(
        String name,
        long address,
        long byteLength,
        boolean readable,
        boolean writable,
        boolean executable
    ) {}

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 1) {
            throw new IllegalArgumentException(
                "REA console preparation script requires one spec file path"
            );
        }
        Path specPath = Path.of(args[0]);
        if (!Files.isRegularFile(specPath, LinkOption.NOFOLLOW_LINKS)) {
            throw new IllegalArgumentException("REA console spec file is not a regular file");
        }
        String content = Files.readString(specPath, StandardCharsets.UTF_8);
        String format = null;
        String expectedLanguage = null;
        String entryHex = null;
        String loader = null;
        List<FileMapSpec> fileMaps = new ArrayList<>();
        List<MemoryRegionSpec> memRegions = new ArrayList<>();

        for (String line : content.split("\n")) {
            if (line.isEmpty()) continue;
            String[] fields = line.split("\t", -1);
            switch (fields[0]) {
                case "meta" -> {
                    if (fields.length != 5) {
                        throw new IllegalArgumentException("Malformed meta record in console spec");
                    }
                    format = fields[1];
                    expectedLanguage = fields[2];
                    entryHex = fields[3];
                    loader = fields[4];
                }
                case "map" -> {
                    if (fields.length != 6) {
                        throw new IllegalArgumentException("Malformed map record in console spec");
                    }
                    String rwx = fields[5];
                    fileMaps.add(new FileMapSpec(
                        fields[1],
                        parseHex(fields[2]),
                        Long.parseLong(fields[3]),
                        Long.parseLong(fields[4]),
                        rwx.indexOf('r') >= 0,
                        rwx.indexOf('w') >= 0,
                        rwx.indexOf('x') >= 0
                    ));
                }
                case "mem" -> {
                    if (fields.length != 5) {
                        throw new IllegalArgumentException("Malformed mem record in console spec");
                    }
                    String rwx = fields[4];
                    memRegions.add(new MemoryRegionSpec(
                        fields[1],
                        parseHex(fields[2]),
                        Long.parseLong(fields[3]),
                        rwx.indexOf('r') >= 0,
                        rwx.indexOf('w') >= 0,
                        rwx.indexOf('x') >= 0
                    ));
                }
                default -> throw new IllegalArgumentException(
                    "Unknown console spec record kind: " + fields[0]
                );
            }
        }

        if (format == null || expectedLanguage == null || entryHex == null || loader == null) {
            throw new IllegalArgumentException("Console spec is missing meta declaration");
        }
        if (!currentProgram.getLanguageID().getIdAsString().equals(expectedLanguage)) {
            throw new IllegalArgumentException(
                "Console preparation language mismatch: expected " + expectedLanguage +
                ", got " + currentProgram.getLanguageID().getIdAsString()
            );
        }

        Memory memory = currentProgram.getMemory();
        AddressSpace space = currentProgram.getAddressFactory().getDefaultAddressSpace();

        if (loader.equals("BinaryLoader")) {
            List<FileBytes> allFileBytes = memory.getAllFileBytes();
            if (allFileBytes.isEmpty()) {
                throw new IllegalStateException("BinaryLoader import did not record FileBytes");
            }
            FileBytes fileBytes = allFileBytes.get(0);

            // Remove the default flat block created by BinaryLoader so we can map
            // exact console segments backed by the same FileBytes.
            for (MemoryBlock block : memory.getBlocks()) {
                boolean backedByFile = false;
                for (MemoryBlockSourceInfo info : block.getSourceInfos()) {
                    if (info.getFileBytes().isPresent()) {
                        backedByFile = true;
                        break;
                    }
                }
                if (backedByFile) {
                    memory.removeBlock(block, monitor);
                }
            }

            for (FileMapSpec map : fileMaps) {
                monitor.checkCancelled();
                if (map.byteLength <= 0) continue;
                Address start = space.getAddress(map.address);
                Address end = space.getAddress(map.address + map.byteLength - 1);
                removeOverlappingBlocks(memory, start, end, true);
                MemoryBlock created = memory.createInitializedBlock(
                    map.name,
                    start,
                    fileBytes,
                    map.fileOffset,
                    map.byteLength,
                    false
                );
                created.setRead(map.readable);
                created.setWrite(map.writable);
                created.setExecute(map.executable);
            }
        }

        for (MemoryRegionSpec region : memRegions) {
            monitor.checkCancelled();
            if (region.byteLength <= 0) continue;
            Address start = space.getAddress(region.address);
            Address end = space.getAddress(region.address + region.byteLength - 1);
            if (hasInitializedOverlap(memory, start, end)) {
                continue;
            }
            removeOverlappingBlocks(memory, start, end, false);
            MemoryBlock created = memory.createUninitializedBlock(
                region.name,
                start,
                region.byteLength,
                false
            );
            created.setRead(region.readable);
            created.setWrite(region.writable);
            created.setExecute(region.executable);
            String lowerName = region.name.toLowerCase();
            if (lowerName.contains("io") || lowerName.contains("ppu") ||
                lowerName.contains("apu") || lowerName.contains("gs")) {
                created.setVolatile(true);
            }
        }

        if (expectedLanguage.equals("x86:LE:16:Real Mode")) {
            applyWonderSwanSegmentContext(space, fileMaps);
        }

        long rawEntryOffset = parseHex(entryHex);
        if (expectedLanguage.startsWith("ARM:") && (rawEntryOffset & 1L) == 1L) {
            long alignedOffset = rawEntryOffset & ~1L;
            Address alignedEntry = space.getAddress(alignedOffset);
            Register tmode = currentProgram.getRegister("TMode");
            if (tmode != null) {
                currentProgram.getProgramContext().setValue(
                    tmode, alignedEntry, alignedEntry, BigInteger.ONE
                );
            }
            rawEntryOffset = alignedOffset;
        }

        Address entry = space.getAddress(rawEntryOffset);
        MemoryBlock entryBlock = memory.getBlock(entry);
        if (entryBlock != null && entryBlock.isInitialized()) {
            addEntryPoint(entry);
            disassemble(entry);
            if (getFunctionAt(entry) == null) {
                createFunction(entry, "entry");
            }
        }

        currentProgram.getOptions(Program.PROGRAM_INFO).setBoolean("REA console prepared", true);
    }

    private void removeOverlappingBlocks(
        Memory memory,
        Address start,
        Address end,
        boolean includeInitialized
    ) throws Exception {
        for (MemoryBlock existing : memory.getBlocks()) {
            if (!includeInitialized && existing.isInitialized()) continue;
            if (existing.getStart().compareTo(end) <= 0 &&
                existing.getEnd().compareTo(start) >= 0) {
                memory.removeBlock(existing, monitor);
            }
        }
    }

    private static boolean hasInitializedOverlap(Memory memory, Address start, Address end) {
        for (MemoryBlock existing : memory.getBlocks()) {
            if (!existing.isInitialized()) continue;
            if (existing.getStart().compareTo(end) <= 0 &&
                existing.getEnd().compareTo(start) >= 0) {
                return true;
            }
        }
        return false;
    }

    private void applyWonderSwanSegmentContext(
        AddressSpace space,
        List<FileMapSpec> fileMaps
    ) throws Exception {
        Register cs = currentProgram.getRegister("CS");
        Register ds = currentProgram.getRegister("DS");
        Register es = currentProgram.getRegister("ES");
        Register ss = currentProgram.getRegister("SS");
        for (FileMapSpec map : fileMaps) {
            long cursor = map.address;
            long mapEnd = map.address + map.byteLength;
            while (cursor < mapEnd) {
                long chunkEnd = Math.min(mapEnd - 1, (cursor & ~0xffffL) + 0xffffL);
                long segSelector = (cursor >>> 4) & 0xf000L;
                Address start = space.getAddress(cursor);
                Address end = space.getAddress(chunkEnd);
                if (cs != null) {
                    currentProgram.getProgramContext().setValue(
                        cs, start, end, BigInteger.valueOf(segSelector)
                    );
                }
                if (ds != null) {
                    currentProgram.getProgramContext().setValue(
                        ds, start, end, BigInteger.ZERO
                    );
                }
                if (es != null) {
                    currentProgram.getProgramContext().setValue(
                        es, start, end, BigInteger.ZERO
                    );
                }
                if (ss != null) {
                    currentProgram.getProgramContext().setValue(
                        ss, start, end, BigInteger.ZERO
                    );
                }
                cursor = chunkEnd + 1;
            }
        }
    }

    private static long parseHex(String value) {
        String clean = value.startsWith("0x") || value.startsWith("0X")
            ? value.substring(2)
            : value;
        return Long.parseUnsignedLong(clean, 16);
    }
}
