import ghidra.app.script.GhidraScript;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.CharDataType;
import ghidra.program.model.data.DWordDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.WordDataType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryBlockSourceInfo;
import ghidra.program.model.symbol.SourceType;
import java.io.InputStream;
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

    private record GbaField(long address, String name, DataType type) {}

    private static final DataType U8 = ByteDataType.dataType;
    private static final DataType U16 = WordDataType.dataType;
    private static final DataType U32 = DWordDataType.dataType;
    private static final long GBA_ROM_BASE = 0x08000000L;

    private static GbaField gbaIo(long offset, String name, DataType type) {
        return new GbaField(0x04000000L + offset, "REG_" + name, type);
    }

    private static final GbaField[] GBA_IO_REGISTERS = {
        gbaIo(0x000, "DISPCNT", U16), gbaIo(0x004, "DISPSTAT", U16), gbaIo(0x006, "VCOUNT", U16),
        gbaIo(0x008, "BG0CNT", U16), gbaIo(0x00A, "BG1CNT", U16), gbaIo(0x00C, "BG2CNT", U16), gbaIo(0x00E, "BG3CNT", U16),
        gbaIo(0x010, "BG0HOFS", U16), gbaIo(0x012, "BG0VOFS", U16), gbaIo(0x014, "BG1HOFS", U16), gbaIo(0x016, "BG1VOFS", U16),
        gbaIo(0x018, "BG2HOFS", U16), gbaIo(0x01A, "BG2VOFS", U16), gbaIo(0x01C, "BG3HOFS", U16), gbaIo(0x01E, "BG3VOFS", U16),
        gbaIo(0x020, "BG2PA", U16), gbaIo(0x022, "BG2PB", U16), gbaIo(0x024, "BG2PC", U16), gbaIo(0x026, "BG2PD", U16),
        gbaIo(0x028, "BG2X", U32), gbaIo(0x02C, "BG2Y", U32),
        gbaIo(0x030, "BG3PA", U16), gbaIo(0x032, "BG3PB", U16), gbaIo(0x034, "BG3PC", U16), gbaIo(0x036, "BG3PD", U16),
        gbaIo(0x038, "BG3X", U32), gbaIo(0x03C, "BG3Y", U32),
        gbaIo(0x040, "WIN0H", U16), gbaIo(0x042, "WIN1H", U16), gbaIo(0x044, "WIN0V", U16), gbaIo(0x046, "WIN1V", U16),
        gbaIo(0x048, "WININ", U16), gbaIo(0x04A, "WINOUT", U16), gbaIo(0x04C, "MOSAIC", U16),
        gbaIo(0x050, "BLDCNT", U16), gbaIo(0x052, "BLDALPHA", U16), gbaIo(0x054, "BLDY", U16),
        gbaIo(0x060, "SOUND1CNT_L", U16), gbaIo(0x062, "SOUND1CNT_H", U16), gbaIo(0x064, "SOUND1CNT_X", U16),
        gbaIo(0x068, "SOUND2CNT_L", U16), gbaIo(0x06C, "SOUND2CNT_H", U16),
        gbaIo(0x070, "SOUND3CNT_L", U16), gbaIo(0x072, "SOUND3CNT_H", U16), gbaIo(0x074, "SOUND3CNT_X", U16),
        gbaIo(0x078, "SOUND4CNT_L", U16), gbaIo(0x07C, "SOUND4CNT_H", U16),
        gbaIo(0x080, "SOUNDCNT_L", U16), gbaIo(0x082, "SOUNDCNT_H", U16), gbaIo(0x084, "SOUNDCNT_X", U16),
        gbaIo(0x088, "SOUNDBIAS", U16),
        gbaIo(0x090, "WAVE_RAM", new ArrayDataType(U8, 16, 1)),
        gbaIo(0x0A0, "FIFO_A", U32), gbaIo(0x0A4, "FIFO_B", U32),
        gbaIo(0x0B0, "DMA0SAD", U32), gbaIo(0x0B4, "DMA0DAD", U32), gbaIo(0x0B8, "DMA0CNT", U32),
        gbaIo(0x0BC, "DMA1SAD", U32), gbaIo(0x0C0, "DMA1DAD", U32), gbaIo(0x0C4, "DMA1CNT", U32),
        gbaIo(0x0C8, "DMA2SAD", U32), gbaIo(0x0CC, "DMA2DAD", U32), gbaIo(0x0D0, "DMA2CNT", U32),
        gbaIo(0x0D4, "DMA3SAD", U32), gbaIo(0x0D8, "DMA3DAD", U32), gbaIo(0x0DC, "DMA3CNT", U32),
        gbaIo(0x100, "TM0CNT_L", U16), gbaIo(0x102, "TM0CNT_H", U16), gbaIo(0x104, "TM1CNT_L", U16), gbaIo(0x106, "TM1CNT_H", U16),
        gbaIo(0x108, "TM2CNT_L", U16), gbaIo(0x10A, "TM2CNT_H", U16), gbaIo(0x10C, "TM3CNT_L", U16), gbaIo(0x10E, "TM3CNT_H", U16),
        gbaIo(0x120, "SIODATA32", U32), gbaIo(0x124, "SIOMULTI2", U16), gbaIo(0x126, "SIOMULTI3", U16),
        gbaIo(0x128, "SIOCNT", U16), gbaIo(0x12A, "SIODATA8", U16),
        gbaIo(0x130, "KEYINPUT", U16), gbaIo(0x132, "KEYCNT", U16), gbaIo(0x134, "RCNT", U16),
        gbaIo(0x140, "JOYCNT", U16), gbaIo(0x150, "JOY_RECV", U32), gbaIo(0x154, "JOY_TRANS", U32), gbaIo(0x158, "JOYSTAT", U16),
        gbaIo(0x200, "IE", U16), gbaIo(0x202, "IF", U16), gbaIo(0x204, "WAITCNT", U16), gbaIo(0x208, "IME", U16),
        gbaIo(0x300, "POSTFLG", U8), gbaIo(0x301, "HALTCNT", U8),
        new GbaField(0x03007FF8L, "BIOS_IRQ_CHECK", U16),
        new GbaField(0x03007FFCL, "BIOS_IRQ_HANDLER", U32),
    };

    private static final GbaField[] GBA_HEADER_FIELDS = {
        new GbaField(GBA_ROM_BASE + 0x04, "GBA_HEADER_LOGO", new ArrayDataType(U8, 156, 1)),
        new GbaField(GBA_ROM_BASE + 0xA0, "GBA_HEADER_TITLE", new ArrayDataType(CharDataType.dataType, 12, 1)),
        new GbaField(GBA_ROM_BASE + 0xAC, "GBA_HEADER_GAME_CODE", new ArrayDataType(CharDataType.dataType, 4, 1)),
        new GbaField(GBA_ROM_BASE + 0xB0, "GBA_HEADER_MAKER_CODE", new ArrayDataType(CharDataType.dataType, 2, 1)),
        new GbaField(GBA_ROM_BASE + 0xB2, "GBA_HEADER_FIXED_96", U8),
        new GbaField(GBA_ROM_BASE + 0xB3, "GBA_HEADER_UNIT_CODE", U8),
        new GbaField(GBA_ROM_BASE + 0xB4, "GBA_HEADER_DEVICE_TYPE", U8),
        new GbaField(GBA_ROM_BASE + 0xBC, "GBA_HEADER_VERSION", U8),
        new GbaField(GBA_ROM_BASE + 0xBD, "GBA_HEADER_CHECKSUM", U8),
    };

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1 || args.length > 2) {
            throw new IllegalArgumentException(
                "REA console preparation script requires a spec path and optional seed snapshot path"
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
        long maxOffset = space.getMaxAddress().getUnsignedOffset();

        if (loader.equals("BinaryLoader")) {
            List<FileBytes> allFileBytes = memory.getAllFileBytes();
            if (allFileBytes.isEmpty()) {
                throw new IllegalStateException("BinaryLoader import did not record FileBytes");
            }
            FileBytes fileBytes = allFileBytes.get(0);
            String execPathRaw = currentProgram.getExecutablePath();
            if (execPathRaw != null && !execPathRaw.isBlank()) {
                Path execPath = Path.of(execPathRaw);
                if (Files.isRegularFile(execPath, LinkOption.NOFOLLOW_LINKS)) {
                    long actualSize = Files.size(execPath);
                    if (fileBytes.getSize() < actualSize) {
                        try (InputStream in = Files.newInputStream(execPath)) {
                            fileBytes = memory.createFileBytes(
                                execPath.getFileName().toString(),
                                0L,
                                actualSize,
                                in,
                                monitor
                            );
                        }
                    }
                }
            }

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
                long endOffset = map.address + map.byteLength - 1;
                if (Long.compareUnsigned(map.address, maxOffset) > 0 ||
                    Long.compareUnsigned(endOffset, maxOffset) > 0) {
                    continue;
                }
                Address start = space.getAddress(map.address);
                Address end = space.getAddress(endOffset);
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
            long endOffset = region.address + region.byteLength - 1;
            if (Long.compareUnsigned(region.address, maxOffset) > 0 ||
                Long.compareUnsigned(endOffset, maxOffset) > 0) {
                continue;
            }
            Address start = space.getAddress(region.address);
            Address end = space.getAddress(endOffset);
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
                lowerName.contains("apu") || lowerName.contains("gs") ||
                lowerName.equals("sram")) {
                created.setVolatile(true);
            }
        }

        if (format.equals("gba")) {
            applyGbaFields(space, memory, maxOffset, GBA_IO_REGISTERS);
            applyGbaFields(space, memory, maxOffset, GBA_HEADER_FIELDS);
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

        // Set platform defaults before caller assertions, and apply assertions
        // before any reset/vector flow creates instructions. Otherwise changing
        // 65816 E/M/X at a reset-reachable address raises ContextChangeException.
        prepareEntryContext(space, memory, rawEntryOffset);
        if (args.length == 2) {
            runScript("ReaGhidraApplySeeds.java", new String[] { args[1] });
        }

        seedEntryAddress(space, memory, maxOffset, rawEntryOffset, "entry");
        seedConsoleVectors(format, space, memory, maxOffset, rawEntryOffset);

        currentProgram.getOptions(Program.PROGRAM_INFO).setString(
            "REA console entry",
            String.format("0x%x", rawEntryOffset)
        );
        currentProgram.getOptions(Program.PROGRAM_INFO).setBoolean("REA console prepared", true);
    }

    /** Platform reset defaults only; caller context seeds may override them. */
    private void prepareEntryContext(AddressSpace space, Memory memory, long rawOffset)
            throws Exception {
        if (!currentProgram.getLanguageID().getIdAsString().equals("65816:LE:16:default")) return;
        Address resetVector = space.getAddress(0xfffcL);
        if (!memory.contains(resetVector) ||
            (memory.getShort(resetVector) & 0xffff) != rawOffset) return;
        if (Long.compareUnsigned(rawOffset, space.getMaxAddress().getUnsignedOffset()) > 0) return;
        Address address = space.getAddress(rawOffset);
        MemoryBlock block = memory.getBlock(address);
        if (block == null || !block.isInitialized()) return;
        for (String name : new String[] { "ctx_EF", "ctx_MF", "ctx_XF" }) {
            Register register = currentProgram.getRegister(name);
            if (register != null) currentProgram.getProgramContext().setValue(
                register, address, address, BigInteger.ONE
            );
        }
    }

    private void seedEntryAddress(
        AddressSpace space,
        Memory memory,
        long maxOffset,
        long rawOffset,
        String name
    ) throws Exception {
        if (Long.compareUnsigned(rawOffset, maxOffset) > 0) return;
        Address address = space.getAddress(rawOffset);
        MemoryBlock block = memory.getBlock(address);
        if (block == null || !block.isInitialized()) return;
        if (name != null) {
            createLabel(address, name, true, SourceType.IMPORTED);
        }
        if (currentProgram.getLanguageID().getIdAsString().equals("65816:LE:16:default")) {
            // Interrupt vectors may alias code entered under a different status.
            // Labels preserve the observation without imposing conflicting modes.
            if (!"entry".equals(name)) return;
            Address resetVector = space.getAddress(0xfffcL);
            if (!memory.contains(resetVector) ||
                (memory.getShort(resetVector) & 0xffff) != rawOffset) return;
        }
        if ("entry".equals(name)) addEntryPoint(address);
        disassemble(address);
        if (name != null && getFunctionAt(address) == null) {
            createFunction(address, name);
        }
    }

    private void seedConsoleVectors(
        String format,
        AddressSpace space,
        Memory memory,
        long maxOffset,
        long primaryEntry
    ) throws Exception {
        switch (format) {
            case "snes" -> {
                long[] vecAddrs = { 0x00ffeaL, 0x00ffeeL, 0x00fffaL, 0x00fffeL };
                String[] vecNames = { "vec_nmi_native", "vec_irq_native", "vec_nmi_emu", "vec_irq_emu" };
                for (int i = 0; i < vecAddrs.length; i++) {
                    Address vecPtr = space.getAddress(vecAddrs[i]);
                    if (!memory.contains(vecPtr) || !memory.contains(vecPtr.add(1))) continue;
                    int target = memory.getShort(vecPtr) & 0xffff;
                    if (target >= 0x8000 && target < 0xffe0 && target != primaryEntry) {
                        seedEntryAddress(space, memory, maxOffset, target, vecNames[i]);
                    }
                }
            }
            case "nes" -> {
                long[] vecAddrs = { 0xfffaL, 0xfffeL };
                String[] vecNames = { "vec_nmi", "vec_irq" };
                for (int i = 0; i < vecAddrs.length; i++) {
                    Address vecPtr = space.getAddress(vecAddrs[i]);
                    if (!memory.contains(vecPtr) || !memory.contains(vecPtr.add(1))) continue;
                    int target = memory.getShort(vecPtr) & 0xffff;
                    if (target >= 0x8000 && target < 0xfffa && target != primaryEntry) {
                        seedEntryAddress(space, memory, maxOffset, target, vecNames[i]);
                    }
                }
            }
            case "gb" -> {
                long[] vecAddrs = { 0x0040L, 0x0048L, 0x0050L, 0x0058L, 0x0060L };
                String[] vecNames = { "int_vblank", "int_stat", "int_timer", "int_serial", "int_joypad" };
                for (int i = 0; i < vecAddrs.length; i++) {
                    seedEntryAddress(space, memory, maxOffset, vecAddrs[i], vecNames[i]);
                }
            }
            case "md" -> {
                long[] vecAddrs = { 0x000070L, 0x000078L };
                String[] vecNames = { "vec_hblank", "vec_vblank" };
                for (int i = 0; i < vecAddrs.length; i++) {
                    Address vecPtr = space.getAddress(vecAddrs[i]);
                    if (!memory.contains(vecPtr) || !memory.contains(vecPtr.add(3))) continue;
                    long target = Integer.toUnsignedLong(memory.getInt(vecPtr));
                    if (target >= 0x200L && target != primaryEntry) {
                        seedEntryAddress(space, memory, maxOffset, target, vecNames[i]);
                    }
                }
            }
            default -> {}
        }
    }

    private void applyGbaFields(
        AddressSpace space,
        Memory memory,
        long maxOffset,
        GbaField[] fields
    ) throws Exception {
        for (GbaField field : fields) {
            long endOffset = field.address() + Math.max(1, field.type().getLength()) - 1;
            if (Long.compareUnsigned(endOffset, maxOffset) > 0) continue;
            Address address = space.getAddress(field.address());
            Address fieldEnd = space.getAddress(endOffset);
            MemoryBlock block = memory.getBlock(address);
            if (block == null || block.getEnd().compareTo(fieldEnd) < 0) continue;
            clearListing(address, fieldEnd);
            createLabel(address, field.name(), true, SourceType.IMPORTED);
            createData(address, field.type());
        }
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
