export type DiffLine = {
  kind: "same" | "added" | "removed" | "gap";
  text: string;
};
/** Bounded line comparison. Large inputs remain available in the full Source view. */
export function sourceDiff(
  original: string,
  candidate: string,
): DiffLine[] | null {
  const before = original.trimEnd().split("\n"),
    after = candidate.trimEnd().split("\n");
  if (before.length > 400 || after.length > 400) return null;
  const table = Array.from(
    { length: before.length + 1 },
    () => new Uint16Array(after.length + 1),
  );
  for (let i = before.length - 1; i >= 0; i--)
    for (let j = after.length - 1; j >= 0; j--)
      table[i][j] =
        before[i] === after[j]
          ? table[i + 1][j + 1] + 1
          : Math.max(table[i + 1][j], table[i][j + 1]);
  const lines: DiffLine[] = [];
  let i = 0,
    j = 0;
  while (i < before.length || j < after.length) {
    if (i < before.length && j < after.length && before[i] === after[j]) {
      lines.push({ kind: "same", text: before[i++] });
      j++;
    } else if (
      i < before.length &&
      (j === after.length || table[i + 1][j] >= table[i][j + 1])
    )
      lines.push({ kind: "removed", text: before[i++] });
    else lines.push({ kind: "added", text: after[j++] });
  }
  if (lines.every((line) => line.kind === "same")) return [];
  const result: DiffLine[] = [];
  let gap = false;
  for (let n = 0; n < lines.length; n++) {
    if (
      lines[n].kind !== "same" ||
      (lines[n - 1] && lines[n - 1].kind !== "same") ||
      (lines[n + 1] && lines[n + 1].kind !== "same")
    ) {
      if (gap && result.length)
        result.push({ kind: "gap", text: "Unchanged lines" });
      result.push(lines[n]);
      gap = false;
    } else gap = true;
  }
  return result;
}
