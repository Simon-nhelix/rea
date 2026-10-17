/** Region `[address, address+length)` of each file; groups of overlapping files. */
export const overlappingRegions = (
  regions: readonly {
    readonly file: string;
    readonly address: number;
    readonly length: number;
  }[],
): string[][] => {
  const groups: { start: number; end: number; files: string[] }[] = [];
  const sorted = [...regions].sort((a, b) => a.address - b.address);
  for (const region of sorted) {
    const end = region.address + region.length;
    const last = groups[groups.length - 1];
    if (last !== undefined && region.address < last.end) {
      last.files.push(region.file);
      last.end = Math.max(last.end, end);
    } else groups.push({ start: region.address, end, files: [region.file] });
  }
  return groups.filter((g) => g.files.length > 1).map((g) => g.files);
};
