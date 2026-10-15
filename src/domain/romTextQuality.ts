import { sjisKanjiLevel } from "./shiftJisTables.js";

/**
 * Caller-selected noise filters for decoded ROM text. They are heuristics for
 * Japanese text: a rejected string is not proven to be data, and an accepted
 * string is not proven to be text.
 */
export interface RomTextFilters {
  /** Reject strings that contain ASCII or half-width katakana. */
  readonly fullwidthOnly: boolean;
  /** Minimum count of full-width hiragana and katakana. */
  readonly minKana: number;
  /** Maximum share of JIS level-2 (and extension) kanji among all kanji. */
  readonly maxLevel2KanjiRatio: number | undefined;
  /** Minimum text_score. */
  readonly minTextScore: number | undefined;
}

export const NO_ROM_TEXT_FILTERS: RomTextFilters = {
  fullwidthOnly: false,
  minKana: 0,
  maxLevel2KanjiRatio: undefined,
  minTextScore: undefined,
};

export const romTextFiltersActive = (filters: RomTextFilters): boolean =>
  filters.fullwidthOnly ||
  filters.minKana > 0 ||
  filters.maxLevel2KanjiRatio !== undefined ||
  filters.minTextScore !== undefined;

/** Character counts used by the filters and by text_score. */
export interface RomTextMeasure {
  readonly characters: number;
  readonly kana: number;
  readonly kanji: number;
  readonly level2Kanji: number;
  readonly halfwidth: number;
  /** Heuristic 0..1 plausibility that the string is Japanese text. */
  readonly score: number;
}

const COMMON_PUNCTUATION = new Set(
  "、。，．！？「」『』（）【】〈〉《》…‥～〜：；“”‘’・ー々ゝゞヽヾ　",
);

const isKana = (code: number): boolean =>
  (code >= 0x3041 && code <= 0x3096) || (code >= 0x30a1 && code <= 0x30fa);
const isKanji = (code: number): boolean =>
  (code >= 0x4e00 && code <= 0x9fff) || (code >= 0xf900 && code <= 0xfaff);
const isFullwidthAlnum = (code: number): boolean =>
  (code >= 0xff10 && code <= 0xff19) ||
  (code >= 0xff21 && code <= 0xff3a) ||
  (code >= 0xff41 && code <= 0xff5a);
const isHalfwidthKana = (code: number): boolean =>
  code >= 0xff61 && code <= 0xff9f;
const isAsciiAlnumOrSpace = (code: number): boolean =>
  code === 0x20 ||
  (code >= 0x30 && code <= 0x39) ||
  (code >= 0x41 && code <= 0x5a) ||
  (code >= 0x61 && code <= 0x7a);

/**
 * Measure decoded text. Newlines are ignored. text_score is the mean of
 * per-character weights (kana and common punctuation highest, level-1 kanji
 * next, level-2 kanji, half-width and rare symbols lowest), halved when one
 * character makes up more than 60% of a string of three or more characters.
 */
export const measureRomText = (text: string): RomTextMeasure => {
  let characters = 0;
  let kana = 0;
  let kanji = 0;
  let level2Kanji = 0;
  let halfwidth = 0;
  let weight = 0;
  const frequency = new Map<string, number>();
  for (const char of text) {
    if (char === "\n") continue;
    const code = char.codePointAt(0) ?? 0;
    characters++;
    frequency.set(char, (frequency.get(char) ?? 0) + 1);
    if (isKana(code)) {
      kana++;
      weight += 1;
    } else if (COMMON_PUNCTUATION.has(char)) {
      weight += 0.9;
    } else if (isKanji(code)) {
      kanji++;
      if (sjisKanjiLevel(char) === 1) {
        weight += 0.8;
      } else {
        level2Kanji++;
        weight += 0.3;
      }
    } else if (isFullwidthAlnum(code)) {
      weight += 0.6;
    } else if (code < 0x80) {
      halfwidth++;
      weight += isAsciiAlnumOrSpace(code) ? 0.5 : 0.2;
    } else if (isHalfwidthKana(code)) {
      halfwidth++;
      weight += 0.15;
    } else {
      weight += 0.1;
    }
  }
  let score = characters === 0 ? 0 : weight / characters;
  if (characters >= 3) {
    const most = Math.max(...frequency.values());
    if (most / characters > 0.6) score *= 0.5;
  }
  return {
    characters,
    kana,
    kanji,
    level2Kanji,
    halfwidth,
    score: Math.round(score * 100) / 100,
  };
};

/** Whether measured text satisfies every active filter. */
export const romTextPassesFilters = (
  measure: RomTextMeasure,
  filters: RomTextFilters,
): boolean => {
  if (filters.fullwidthOnly && measure.halfwidth > 0) return false;
  if (measure.kana < filters.minKana) return false;
  if (
    filters.maxLevel2KanjiRatio !== undefined &&
    measure.kanji > 0 &&
    measure.level2Kanji / measure.kanji > filters.maxLevel2KanjiRatio
  )
    return false;
  if (
    filters.minTextScore !== undefined &&
    measure.score < filters.minTextScore
  )
    return false;
  return true;
};
