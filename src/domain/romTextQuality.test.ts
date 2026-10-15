import { describe, expect, it } from "vitest";
import {
  measureRomText,
  NO_ROM_TEXT_FILTERS,
  romTextPassesFilters,
} from "./romTextQuality.js";

describe("ROM text quality", () => {
  it("counts kana, kanji levels and half-width characters", () => {
    // 傭 (SJIS 9762) and 義 (8B60) are level 1; 弌 (989F) and 丐 (98A0) level 2.
    expect(measureRomText("どうしますか？\n傭兵")).toMatchObject({
      characters: 9,
      kana: 6,
      kanji: 2,
      level2Kanji: 0,
      halfwidth: 0,
    });
    expect(measureRomText("弌丐義")).toMatchObject({
      kanji: 3,
      level2Kanji: 2,
    });
    expect(measureRomText("mT控bmU)")).toMatchObject({
      halfwidth: 6,
      kanji: 1,
    });
  });

  it("scores dialogue above byte noise and penalizes repetition", () => {
    const dialogue = measureRomText("「どうしますか？」").score;
    const noise = measureRomText("mT控bmU)").score;
    const level2 = measureRomText("弌丐").score;
    expect(dialogue).toBeGreaterThan(0.9);
    expect(noise).toBeLessThan(0.6);
    expect(level2).toBeLessThan(0.6);
    expect(measureRomText("あああああ").score).toBe(0.5);
    expect(measureRomText("").score).toBe(0);
  });

  it("applies each caller-selected filter", () => {
    const pass = (text: string, filters: Partial<typeof NO_ROM_TEXT_FILTERS>) =>
      romTextPassesFilters(measureRomText(text), {
        ...NO_ROM_TEXT_FILTERS,
        ...filters,
      });
    expect(pass("ﾀﾞｶﾞｰ", {})).toBe(true);
    expect(pass("ﾀﾞｶﾞｰ", { fullwidthOnly: true })).toBe(false);
    expect(pass("傭兵", { minKana: 1 })).toBe(false);
    expect(pass("傭兵です", { minKana: 2 })).toBe(true);
    expect(pass("弌丐義", { maxLevel2KanjiRatio: 0.5 })).toBe(false);
    expect(pass("傭兵", { maxLevel2KanjiRatio: 0 })).toBe(true);
    expect(pass("mT控bmU)", { minTextScore: 0.6 })).toBe(false);
  });
});
