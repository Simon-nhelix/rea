import {
  dosMzDeclaredImageByteLength,
  readDosMzDeclarations,
} from "./dosMz.js";
import { err, ok, type Result } from "./result.js";

/**
 * DOS extender Linear Executable (LE) and OS/2-style LX modules, as linked by
 * Watcom wlink for DOS/4GW, PMODE/W, DOS/32A and similar extenders.
 *
 * This module owns the interpretation of the LE/LX header, object table,
 * object page map and internal fixup records. Consumers (console admission,
 * Ghidra preparation, ROM text tools, code-reference scans) use these parsed
 * facts instead of reading the raw tables again.
 */

export type DosLinearSignature = "LE" | "LX";

/** Physical page state declared by the object page map. */
export type DosLinearPageKind =
  | "valid"
  | "iterated"
  | "invalid"
  | "zero"
  | "range"
  | "compressed"
  | "unknown";

export interface DosLinearPage {
  /** 1-based logical page number in the object page map. */
  readonly logicalPage: number;
  readonly kind: DosLinearPageKind;
  /** Absolute file offset of the page bytes; null when not file-backed. */
  readonly fileOffset: number | null;
  /** File bytes of the page; the rest of the page is zero at load time. */
  readonly byteLength: number;
}

export interface DosLinearObject {
  /** 1-based object number used by fixups and the entry point. */
  readonly number: number;
  readonly virtualAddress: number;
  readonly virtualSize: number;
  readonly flags: number;
  readonly readable: boolean;
  readonly writable: boolean;
  readonly executable: boolean;
  /** OSF_OBJ_BIG: 32-bit default operand size. */
  readonly big: boolean;
  readonly pages: readonly DosLinearPage[];
}

/** Source field written by the loader at a fixup site. */
export type DosLinearFixupSource =
  | "byte"
  | "selector16"
  | "pointer16_16"
  | "offset16"
  | "pointer16_32"
  | "offset32"
  | "relative32";

export interface DosLinearFixup {
  readonly sourceAddress: number;
  /** File offset of the first source byte, when that byte is file-backed. */
  readonly sourceFileOffset: number | null;
  readonly sourceObject: number;
  readonly source: DosLinearFixupSource;
  readonly targetObject: number;
  readonly targetOffset: number;
  /** Flat linear address: target object base plus target offset. */
  readonly targetAddress: number;
}

export interface DosLinearSkippedFixups {
  readonly importByOrdinal: number;
  readonly importByName: number;
  readonly entryTable: number;
  readonly unknownSource: number;
  readonly unknownObject: number;
}

export interface DosLinearExecutable {
  readonly signature: DosLinearSignature;
  readonly headerOffset: number;
  /** Start of the MZ stub whose e_lfanew or image end led to the header. */
  readonly containerOffset: number;
  /** Absolute offset that page offsets are relative to. */
  readonly dataPagesOffset: number;
  /** 0 when the declared data-pages offset was absolute, else containerOffset. */
  readonly dataPagesBase: number;
  readonly pageSize: number;
  readonly moduleFlags: number;
  readonly objects: readonly DosLinearObject[];
  readonly entry: {
    readonly object: number;
    readonly offset: number;
    readonly address: number;
  };
  readonly stack: { readonly object: number; readonly offset: number };
  /** Internal fixups, one per source address, ordered by source address. */
  readonly fixups: readonly DosLinearFixup[];
  readonly skippedFixups: DosLinearSkippedFixups;
}

export interface DosLinearHeaderLocation {
  readonly signature: DosLinearSignature;
  readonly headerOffset: number;
  readonly containerOffset: number;
}

const LINEAR_HEADER_BYTES = 0xac;
const OBJECT_ENTRY_BYTES = 24;
const MAX_STUB_HOPS = 8;
const MAX_OBJECTS = 4096;
const MAX_PAGES = 1 << 20;

const linearSignatureAt = (
  bytes: Uint8Array,
  offset: number,
): DosLinearSignature | undefined => {
  if (offset < 0 || offset + 4 > bytes.length) return undefined;
  if (bytes[offset] !== 0x4c) return undefined;
  // Byte order and word order 0 identify a little-endian 386 module.
  if (bytes[offset + 2] !== 0 || bytes[offset + 3] !== 0) return undefined;
  if (bytes[offset + 1] === 0x45) return "LE";
  if (bytes[offset + 1] === 0x58) return "LX";
  return undefined;
};

const isMzAt = (bytes: Uint8Array, offset: number): boolean =>
  offset + 28 <= bytes.length &&
  bytes[offset] === 0x4d &&
  bytes[offset + 1] === 0x5a;

/**
 * Find the LE/LX header of a DOS extender executable. The header is reached
 * through the stub's e_lfanew, or by following bound stubs: an extender stub
 * (for example DOS4GW.EXE bound by 4GWBIND) followed by the program's own MZ
 * stub or the LE header at the end of each stub image.
 */
export const locateDosLinearHeader = (
  bytes: Uint8Array,
): Result<DosLinearHeaderLocation, string> => {
  if (!isMzAt(bytes, 0)) return err("not a DOS MZ executable");
  const buffer = Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  let container = 0;
  for (let hop = 0; hop < MAX_STUB_HOPS; hop++) {
    const header = buffer.subarray(container);
    const headerParagraphs = header.readUInt16LE(8);
    if (headerParagraphs * 16 >= 0x40 && header.length >= 0x40) {
      const lfanew = header.readUInt32LE(0x3c);
      if (lfanew >= 0x40) {
        const candidate = container + lfanew;
        const signature = linearSignatureAt(bytes, candidate);
        if (signature !== undefined)
          return ok({
            signature,
            headerOffset: candidate,
            containerOffset: container,
          });
      }
    }
    const declarations = readDosMzDeclarations(header);
    if (!declarations.ok) break;
    const extent = dosMzDeclaredImageByteLength(declarations.value);
    if (!extent.ok) break;
    const next = container + extent.value;
    if (next <= container || next + 4 > bytes.length) break;
    const signature = linearSignatureAt(bytes, next);
    if (signature !== undefined)
      return ok({ signature, headerOffset: next, containerOffset: container });
    if (bytes[next] === 0x42 && bytes[next + 1] === 0x57)
      return err(
        `DOS/16M BW module at file offset ${String(next)} is not an LE/LX module`,
      );
    if (!isMzAt(bytes, next)) break;
    container = next;
  }
  return err("no LE/LX header found after the DOS stub");
};

const pageKind = (
  signature: DosLinearSignature,
  flags: number,
): DosLinearPageKind => {
  switch (flags) {
    case 0:
      return "valid";
    case 1:
      return "iterated";
    case 2:
      return "invalid";
    case 3:
      return "zero";
    case 4:
      return signature === "LX" ? "range" : "unknown";
    case 5:
      return signature === "LX" ? "compressed" : "unknown";
    default:
      return "unknown";
  }
};

const SOURCE_TYPES: Readonly<Record<number, DosLinearFixupSource>> = {
  0x00: "byte",
  0x02: "selector16",
  0x03: "pointer16_16",
  0x05: "offset16",
  0x06: "pointer16_32",
  0x07: "offset32",
  0x08: "relative32",
};

/**
 * Parse a complete LE/LX executable. Only internal-reference fixups are
 * resolved; DOS extenders do not import modules, and import or entry-table
 * fixups are counted in `skippedFixups`.
 */
export const parseDosLinearExecutable = (
  bytes: Uint8Array,
): Result<DosLinearExecutable, string> => {
  const located = locateDosLinearHeader(bytes);
  if (!located.ok) return located;
  const { signature, headerOffset, containerOffset } = located.value;
  const buffer = Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  if (headerOffset + LINEAR_HEADER_BYTES > buffer.length)
    return err(`truncated ${signature} header`);
  const h = (field: number) => buffer.readUInt32LE(headerOffset + field);
  const pageCount = h(0x14);
  const pageSize = h(0x28);
  const pageShiftOrLast = h(0x2c);
  const objectTable = h(0x40);
  const objectCount = h(0x44);
  const pageMap = h(0x48);
  const fixupPageTable = h(0x68);
  const fixupRecordTable = h(0x6c);
  const declaredDataPages = h(0x80);
  if (pageSize === 0 || pageSize > 0x10000 || (pageSize & (pageSize - 1)) !== 0)
    return err(`${signature} page size ${String(pageSize)} is not supported`);
  if (pageCount > MAX_PAGES) return err(`${signature} declares too many pages`);
  if (objectCount === 0 || objectCount > MAX_OBJECTS)
    return err(`${signature} declares ${String(objectCount)} objects`);
  const tableEnd = (start: number, length: number) =>
    headerOffset + start + length <= buffer.length;
  if (!tableEnd(objectTable, objectCount * OBJECT_ENTRY_BYTES))
    return err(`${signature} object table lies outside the file`);
  const mapEntryBytes = signature === "LE" ? 4 : 8;
  if (!tableEnd(pageMap, pageCount * mapEntryBytes))
    return err(`${signature} object page map lies outside the file`);

  // Data pages follow the header, loader section and fixup section. An
  // absolute offset that points back into a bound stub was written relative
  // to the program's own stub instead.
  // Data pages follow the loader and fixup tables. Watcom writes the offset
  // from the start of the file; once an extender stub is bound in front, the
  // same value is relative to the program's own stub instead.
  const tablesStart =
    headerOffset +
    Math.max(fixupRecordTable, pageMap + pageCount * mapEntryBytes);
  const lastPhysicalEnd = (base: number) =>
    base + declaredDataPages + Math.max(0, pageCount - 1) * pageSize;
  const plausible = (base: number) =>
    base + declaredDataPages >= tablesStart &&
    (signature === "LX" || lastPhysicalEnd(base) <= buffer.length);
  const dataPagesBase =
    containerOffset === 0 || plausible(0)
      ? 0
      : plausible(containerOffset)
        ? containerOffset
        : 0;
  const dataPagesOffset = dataPagesBase + declaredDataPages;

  const pageEntry = (logical: number): DosLinearPage => {
    const at = headerOffset + pageMap + (logical - 1) * mapEntryBytes;
    if (signature === "LE") {
      // Watcom wlink stores the 24-bit physical page number high byte first.
      const physical =
        (buffer[at]! << 16) | (buffer[at + 1]! << 8) | buffer[at + 2]!;
      const kind = pageKind(signature, buffer[at + 3]!);
      if (kind !== "valid" || physical === 0 || physical > pageCount)
        return { logicalPage: logical, kind, fileOffset: null, byteLength: 0 };
      const byteLength =
        physical === pageCount && pageShiftOrLast > 0
          ? Math.min(pageShiftOrLast, pageSize)
          : pageSize;
      return {
        logicalPage: logical,
        kind,
        fileOffset: dataPagesOffset + (physical - 1) * pageSize,
        byteLength,
      };
    }
    const offset = buffer.readUInt32LE(at);
    const size = buffer.readUInt16LE(at + 4);
    const kind = pageKind(signature, buffer.readUInt16LE(at + 6));
    if (kind !== "valid")
      return { logicalPage: logical, kind, fileOffset: null, byteLength: 0 };
    const shift = pageShiftOrLast & 0x1f;
    return {
      logicalPage: logical,
      kind,
      fileOffset: dataPagesOffset + offset * 2 ** shift,
      byteLength: Math.min(size, pageSize),
    };
  };

  const objects: DosLinearObject[] = [];
  for (let index = 0; index < objectCount; index++) {
    const at = headerOffset + objectTable + index * OBJECT_ENTRY_BYTES;
    const virtualSize = buffer.readUInt32LE(at);
    const virtualAddress = buffer.readUInt32LE(at + 4);
    const flags = buffer.readUInt32LE(at + 8);
    const firstPage = buffer.readUInt32LE(at + 12);
    const objectPages = buffer.readUInt32LE(at + 16);
    if (
      objectPages > 0 &&
      (firstPage < 1 || firstPage + objectPages - 1 > pageCount)
    )
      return err(
        `${signature} object ${String(index + 1)} page range lies outside the page map`,
      );
    if (objectPages * pageSize > virtualSize + pageSize)
      return err(
        `${signature} object ${String(index + 1)} has more pages than its virtual size`,
      );
    if (virtualAddress + virtualSize > 0x1_0000_0000)
      return err(
        `${signature} object ${String(index + 1)} extends past the 32-bit address space`,
      );
    const pages: DosLinearPage[] = [];
    for (let page = 0; page < objectPages; page++) {
      const entry = pageEntry(firstPage + page);
      if (
        entry.fileOffset !== null &&
        entry.fileOffset + entry.byteLength > buffer.length
      )
        return err(
          `${signature} page ${String(entry.logicalPage)} lies outside the file`,
        );
      pages.push(entry);
    }
    objects.push({
      number: index + 1,
      virtualAddress,
      virtualSize,
      flags,
      readable: (flags & 0x1) !== 0,
      writable: (flags & 0x2) !== 0,
      executable: (flags & 0x4) !== 0,
      big: (flags & 0x2000) !== 0,
      pages,
    });
  }
  const sorted = [...objects].sort(
    (a, b) => a.virtualAddress - b.virtualAddress,
  );
  for (let i = 1; i < sorted.length; i++) {
    const previous = sorted[i - 1]!;
    if (
      previous.virtualAddress + previous.virtualSize >
      sorted[i]!.virtualAddress
    )
      return err(
        `${signature} objects ${String(previous.number)} and ${String(sorted[i]!.number)} overlap`,
      );
  }

  const entryObject = h(0x18);
  const entryOffset = h(0x1c);
  const entryOwner = objects[entryObject - 1];
  if (entryOwner === undefined)
    return err(
      `${signature} entry object ${String(entryObject)} does not exist`,
    );

  const fixups = parseFixups({
    buffer,
    signature,
    headerOffset,
    pageCount,
    pageSize,
    fixupPageTable,
    fixupRecordTable,
    objects,
  });
  if (!fixups.ok) return fixups;

  return ok({
    signature,
    headerOffset,
    containerOffset,
    dataPagesOffset,
    dataPagesBase,
    pageSize,
    moduleFlags: h(0x10),
    objects,
    entry: {
      object: entryObject,
      offset: entryOffset,
      address: (entryOwner.virtualAddress + entryOffset) >>> 0,
    },
    stack: { object: h(0x20), offset: h(0x24) },
    fixups: fixups.value.fixups,
    skippedFixups: fixups.value.skipped,
  });
};

/** File offset of a linear address, when an object page backs that byte. */
export const dosLinearFileOffset = (
  module: Pick<DosLinearExecutable, "objects" | "pageSize">,
  address: number,
): number | null => {
  for (const object of module.objects) {
    if (
      address < object.virtualAddress ||
      address >= object.virtualAddress + object.virtualSize
    )
      continue;
    const relative = address - object.virtualAddress;
    const page = object.pages[Math.floor(relative / module.pageSize)];
    if (page?.fileOffset === undefined || page.fileOffset === null) return null;
    const within = relative % module.pageSize;
    return within < page.byteLength ? page.fileOffset + within : null;
  }
  return null;
};

/** Linear address of a file offset inside a file-backed object page. */
export const dosLinearAddressOfFileOffset = (
  module: Pick<DosLinearExecutable, "objects" | "pageSize">,
  fileOffset: number,
): number | null => {
  for (const object of module.objects) {
    for (let index = 0; index < object.pages.length; index++) {
      const page = object.pages[index]!;
      if (
        page.fileOffset !== null &&
        fileOffset >= page.fileOffset &&
        fileOffset < page.fileOffset + page.byteLength
      )
        return (
          object.virtualAddress +
          index * module.pageSize +
          (fileOffset - page.fileOffset)
        );
    }
  }
  return null;
};

/** One contiguous file-backed run of an object, for loaders and scanners. */
export interface DosLinearMappedRun {
  readonly object: number;
  readonly virtualAddress: number;
  readonly fileOffset: number;
  readonly byteLength: number;
  readonly executable: boolean;
  readonly writable: boolean;
}

/** Merge consecutive full pages that are also consecutive in the file. */
export const dosLinearMappedRuns = (
  module: Pick<DosLinearExecutable, "objects" | "pageSize">,
): DosLinearMappedRun[] => {
  const runs: DosLinearMappedRun[] = [];
  for (const object of module.objects) {
    let current:
      | {
          virtualAddress: number;
          fileOffset: number;
          byteLength: number;
        }
      | undefined;
    const flush = () => {
      if (current !== undefined && current.byteLength > 0)
        runs.push({
          object: object.number,
          ...current,
          executable: object.executable,
          writable: object.writable,
        });
      current = undefined;
    };
    object.pages.forEach((page, index) => {
      const virtualAddress = object.virtualAddress + index * module.pageSize;
      const byteLength = Math.min(
        page.byteLength,
        object.virtualSize - index * module.pageSize,
      );
      if (page.fileOffset === null || byteLength <= 0) {
        flush();
        return;
      }
      if (
        current !== undefined &&
        current.virtualAddress + current.byteLength === virtualAddress &&
        current.fileOffset + current.byteLength === page.fileOffset
      ) {
        current.byteLength += byteLength;
      } else {
        flush();
        current = { virtualAddress, fileOffset: page.fileOffset, byteLength };
      }
      if (byteLength < module.pageSize) flush();
    });
    flush();
  }
  return runs;
};

/** Bytes the DOS extender writes at a fixup site, little-endian. */
export const dosLinearFixupPatch = (
  fixup: DosLinearFixup,
): Uint8Array | undefined => {
  const out = Buffer.alloc(4);
  switch (fixup.source) {
    case "offset32":
      out.writeUInt32LE(fixup.targetAddress >>> 0);
      return out;
    case "pointer16_32":
      // The selector half is chosen by the extender at run time.
      out.writeUInt32LE(fixup.targetAddress >>> 0);
      return out;
    case "relative32":
      out.writeInt32LE((fixup.targetAddress - (fixup.sourceAddress + 4)) | 0);
      return out;
    case "offset16":
    case "pointer16_16":
      // 16-bit objects are addressed through their own selector.
      out.writeUInt16LE(fixup.targetOffset & 0xffff);
      return out.subarray(0, 2);
    case "byte":
      return Uint8Array.of(fixup.targetOffset & 0xff);
    case "selector16":
      return undefined;
  }
};

/**
 * The file bytes as the extender leaves them after loading: every internal
 * fixup is written at its file offset, so pointer slots and relocated operands
 * read as addresses. File offsets are unchanged; bytes of a fixup that fall
 * outside file-backed pages (zero-filled tails) are dropped.
 */
export const dosLinearRelocatedFileBytes = (
  fileBytes: Uint8Array,
  module: DosLinearExecutable,
): Buffer => {
  const relocated = Buffer.from(fileBytes);
  for (const fixup of module.fixups) {
    const patch = dosLinearFixupPatch(fixup);
    if (patch === undefined) continue;
    // A field may cross a page boundary into a non-adjacent file page.
    for (let index = 0; index < patch.length; index++) {
      const offset = dosLinearFileOffset(module, fixup.sourceAddress + index);
      if (offset !== null && offset < relocated.length)
        relocated[offset] = patch[index]!;
    }
  }
  return relocated;
};

const parseFixups = (input: {
  readonly buffer: Buffer;
  readonly signature: DosLinearSignature;
  readonly headerOffset: number;
  readonly pageCount: number;
  readonly pageSize: number;
  readonly fixupPageTable: number;
  readonly fixupRecordTable: number;
  readonly objects: readonly DosLinearObject[];
}): Result<
  { fixups: DosLinearFixup[]; skipped: DosLinearSkippedFixups },
  string
> => {
  const {
    buffer,
    signature,
    headerOffset,
    pageCount,
    pageSize,
    fixupPageTable,
    fixupRecordTable,
    objects,
  } = input;
  const skipped = {
    importByOrdinal: 0,
    importByName: 0,
    entryTable: 0,
    unknownSource: 0,
    unknownObject: 0,
  };
  if (fixupPageTable === 0 || pageCount === 0)
    return ok({ fixups: [], skipped });
  const pageTableAt = headerOffset + fixupPageTable;
  if (pageTableAt + (pageCount + 1) * 4 > buffer.length)
    return err(`${signature} fixup page table lies outside the file`);
  const recordsAt = headerOffset + fixupRecordTable;
  const owner = new Map<number, { object: DosLinearObject; index: number }>();
  for (const object of objects)
    object.pages.forEach((page, index) =>
      owner.set(page.logicalPage, { object, index }),
    );
  const bySource = new Map<number, DosLinearFixup>();
  for (let logical = 1; logical <= pageCount; logical++) {
    const start = buffer.readUInt32LE(pageTableAt + (logical - 1) * 4);
    const end = buffer.readUInt32LE(pageTableAt + logical * 4);
    if (end < start || recordsAt + end > buffer.length)
      return err(
        `${signature} fixup records of page ${String(logical)} lie outside the file`,
      );
    const page = owner.get(logical);
    let at = recordsAt + start;
    const limit = recordsAt + end;
    const need = (count: number): boolean => at + count <= limit;
    while (at < limit) {
      if (!need(2))
        return err(
          `${signature} truncated fixup record in page ${String(logical)}`,
        );
      const sourceType = buffer[at]!;
      const flags = buffer[at + 1]!;
      at += 2;
      const hasList = (sourceType & 0x20) !== 0;
      let listCount = 0;
      let singleOffset = 0;
      if (hasList) {
        if (!need(1)) return err(`${signature} truncated fixup source list`);
        listCount = buffer[at]!;
        at += 1;
      } else {
        if (!need(2)) return err(`${signature} truncated fixup source offset`);
        singleOffset = buffer.readInt16LE(at);
        at += 2;
      }
      const wideOrdinal = (flags & 0x40) !== 0;
      const readOrdinal = (): number | undefined => {
        if (!need(wideOrdinal ? 2 : 1)) return undefined;
        const value = wideOrdinal ? buffer.readUInt16LE(at) : buffer[at]!;
        at += wideOrdinal ? 2 : 1;
        return value;
      };
      const readSized = (wide: boolean): number | undefined => {
        if (!need(wide ? 4 : 2)) return undefined;
        const value = wide ? buffer.readUInt32LE(at) : buffer.readUInt16LE(at);
        at += wide ? 4 : 2;
        return value;
      };
      const kind = SOURCE_TYPES[sourceType & 0x0f];
      const targetType = flags & 0x03;
      let targetObject: number | undefined;
      let targetOffset = 0;
      if (targetType === 0) {
        targetObject = readOrdinal();
        if (targetObject === undefined)
          return err(`${signature} truncated fixup target`);
        if ((sourceType & 0x0f) !== 0x02) {
          const offset = readSized((flags & 0x10) !== 0);
          if (offset === undefined)
            return err(`${signature} truncated fixup target offset`);
          targetOffset = offset;
        }
      } else if (targetType === 1) {
        if (readOrdinal() === undefined)
          return err(`${signature} truncated import`);
        const ordinalBytes =
          (flags & 0x80) !== 0 ? 1 : (flags & 0x10) !== 0 ? 4 : 2;
        if (!need(ordinalBytes)) return err(`${signature} truncated import`);
        at += ordinalBytes;
      } else if (targetType === 2) {
        if (readOrdinal() === undefined)
          return err(`${signature} truncated import`);
        if (readSized((flags & 0x10) !== 0) === undefined)
          return err(`${signature} truncated import`);
      } else if (readOrdinal() === undefined) {
        return err(`${signature} truncated entry-table fixup`);
      }
      if ((flags & 0x04) !== 0) {
        const additive = readSized((flags & 0x20) !== 0);
        if (additive === undefined)
          return err(`${signature} truncated additive`);
        targetOffset = (targetOffset + additive) >>> 0;
      }
      const offsets: number[] = [];
      if (hasList) {
        if (!need(listCount * 2))
          return err(`${signature} truncated source list`);
        for (let i = 0; i < listCount; i++)
          offsets.push(buffer.readInt16LE(at + i * 2));
        at += listCount * 2;
      } else {
        offsets.push(singleOffset);
      }
      const count = offsets.length;
      if (targetType === 1) {
        skipped.importByOrdinal += count;
        continue;
      }
      if (targetType === 2) {
        skipped.importByName += count;
        continue;
      }
      if (targetType === 3) {
        skipped.entryTable += count;
        continue;
      }
      if (kind === undefined || page === undefined) {
        skipped.unknownSource += count;
        continue;
      }
      const target = objects[(targetObject ?? 0) - 1];
      if (target === undefined) {
        skipped.unknownObject += count;
        continue;
      }
      const pageBase = page.object.virtualAddress + page.index * pageSize;
      for (const offset of offsets) {
        const sourceAddress = pageBase + offset;
        if (bySource.has(sourceAddress)) continue;
        bySource.set(sourceAddress, {
          sourceAddress,
          sourceFileOffset: null,
          sourceObject: page.object.number,
          source: kind,
          targetObject: target.number,
          targetOffset,
          targetAddress: (target.virtualAddress + targetOffset) >>> 0,
        });
      }
    }
  }
  const module = { objects, pageSize };
  const fixups = [...bySource.values()]
    .sort((a, b) => a.sourceAddress - b.sourceAddress)
    .map((fixup) => ({
      ...fixup,
      sourceFileOffset: dosLinearFileOffset(module, fixup.sourceAddress),
    }));
  return ok({ fixups, skipped });
};
