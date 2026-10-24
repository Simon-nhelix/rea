/** Lazily built Shift-JIS (WHATWG shift_jis / CP932) lookup tables. */

let cachedEncodeMap: Map<string, Uint8Array> | undefined;
let cachedDoubleByteDecode: readonly (string | undefined)[] | undefined;

const SJIS_LEAD_RANGES: readonly (readonly [number, number])[] = [
  [0x81, 0x9f],
  [0xe0, 0xfc],
];

/** Character → Shift-JIS bytes, preferring the first (lowest) code. */
export const getSjisEncodeMap = (): ReadonlyMap<string, Uint8Array> => {
  if (cachedEncodeMap !== undefined) return cachedEncodeMap;
  const decoder = new TextDecoder("shift-jis", { fatal: true });
  const map = new Map<string, Uint8Array>();
  // Single-byte ASCII & half-width katakana
  for (let b = 0x20; b <= 0xdf; b++) {
    if (b > 0x7e && b < 0xa1) continue;
    try {
      const char = decoder.decode(Uint8Array.of(b));
      if (!map.has(char)) map.set(char, Uint8Array.of(b));
    } catch {
      // skip unmapped byte
    }
  }
  for (const [leadStart, leadEnd] of SJIS_LEAD_RANGES) {
    for (let lead = leadStart; lead <= leadEnd; lead++) {
      for (let trail = 0x40; trail <= 0xfc; trail++) {
        if (trail === 0x7f) continue;
        try {
          const bytes = Uint8Array.of(lead, trail);
          const char = decoder.decode(bytes);
          if (char.length === 1 && !map.has(char)) map.set(char, bytes);
        } catch {
          // skip unmapped pair
        }
      }
    }
  }
  cachedEncodeMap = map;
  return map;
};

const isPrivateUse = (code: number): boolean =>
  code >= 0xe000 && code <= 0xf8ff;

/**
 * Two-byte Shift-JIS code (lead << 8 | trail) → character. Codes that do not
 * decode to exactly one assigned character (including the user-defined area,
 * which decodes to private-use code points) are undefined.
 */
export const getSjisDoubleByteDecodeTable = (): readonly (
  | string
  | undefined
)[] => {
  if (cachedDoubleByteDecode !== undefined) return cachedDoubleByteDecode;
  const decoder = new TextDecoder("shift-jis", { fatal: true });
  const table = Array.from<string | undefined>({ length: 0x10000 });
  for (const [leadStart, leadEnd] of SJIS_LEAD_RANGES) {
    for (let lead = leadStart; lead <= leadEnd; lead++) {
      for (let trail = 0x40; trail <= 0xfc; trail++) {
        if (trail === 0x7f) continue;
        try {
          const char = decoder.decode(Uint8Array.of(lead, trail));
          const code = char.codePointAt(0) ?? 0xfffd;
          if (char.length === 1 && code !== 0xfffd && !isPrivateUse(code))
            table[(lead << 8) | trail] = char;
        } catch {
          // unmapped pair stays undefined
        }
      }
    }
  }
  cachedDoubleByteDecode = table;
  return table;
};

/** JIS X 0208 kanji level of a character, from its Shift-JIS code. */
export const sjisKanjiLevel = (char: string): 1 | 2 | undefined => {
  const bytes = getSjisEncodeMap().get(char);
  if (bytes?.length !== 2) return undefined;
  const code = ((bytes[0] ?? 0) << 8) | (bytes[1] ?? 0);
  if (code >= 0x889f && code <= 0x9872) return 1;
  // Level 2 plus the NEC/IBM extension kanji rows, which are rarer still.
  if (
    (code >= 0x989f && code <= 0xeaa4) ||
    (code >= 0xed40 && code <= 0xeefc) ||
    (code >= 0xfa40 && code <= 0xfc4b)
  )
    return 2;
  return undefined;
};
