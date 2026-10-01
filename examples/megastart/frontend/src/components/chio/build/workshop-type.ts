import type { EmoteGlyph } from "./workshop-deck";
import type { PixelPainter } from "./workshop-pixels";

/** 5x7 terminal capitals, authored as rows. The engraved faceplate font in
 * pixelslab/glyphs.ts is not reused: its stepped A belongs to PLAYGROUND. */
const FONT: Record<string, string> = {
  A: ".###.|#...#|#...#|#####|#...#|#...#|#...#",
  B: "####.|#...#|#...#|####.|#...#|#...#|####.",
  C: ".###.|#...#|#....|#....|#....|#...#|.###.",
  D: "###..|#..#.|#...#|#...#|#...#|#..#.|###..",
  E: "#####|#....|#....|####.|#....|#....|#####",
  F: "#####|#....|#....|####.|#....|#....|#....",
  G: ".###.|#...#|#....|#.###|#...#|#...#|.####",
  H: "#...#|#...#|#...#|#####|#...#|#...#|#...#",
  I: ".###.|..#..|..#..|..#..|..#..|..#..|.###.",
  J: "..###|...#.|...#.|...#.|...#.|#..#.|.##..",
  K: "#...#|#..#.|#.#..|##...|#.#..|#..#.|#...#",
  L: "#....|#....|#....|#....|#....|#....|#####",
  M: "#...#|##.##|#.#.#|#.#.#|#...#|#...#|#...#",
  N: "#...#|#...#|##..#|#.#.#|#..##|#...#|#...#",
  O: ".###.|#...#|#...#|#...#|#...#|#...#|.###.",
  P: "####.|#...#|#...#|####.|#....|#....|#....",
  Q: ".###.|#...#|#...#|#...#|#.#.#|#..#.|.##.#",
  R: "####.|#...#|#...#|####.|#.#..|#..#.|#...#",
  S: ".####|#....|#....|.###.|....#|....#|####.",
  T: "#####|..#..|..#..|..#..|..#..|..#..|..#..",
  U: "#...#|#...#|#...#|#...#|#...#|#...#|.###.",
  V: "#...#|#...#|#...#|#...#|#...#|.#.#.|..#..",
  W: "#...#|#...#|#...#|#.#.#|#.#.#|#.#.#|.#.#.",
  X: "#...#|#...#|.#.#.|..#..|.#.#.|#...#|#...#",
  Y: "#...#|#...#|.#.#.|..#..|..#..|..#..|..#..",
  Z: "#####|....#|...#.|..#..|.#...|#....|#####",
  0: ".###.|#...#|#..##|#.#.#|##..#|#...#|.###.",
  1: "..#..|.##..|..#..|..#..|..#..|..#..|.###.",
  2: ".###.|#...#|....#|...#.|..#..|.#...|#####",
  3: "####.|....#|....#|.###.|....#|....#|####.",
  4: "...#.|..##.|.#.#.|#..#.|#####|...#.|...#.",
  5: "#####|#....|####.|....#|....#|#...#|.###.",
  6: "..##.|.#...|#....|####.|#...#|#...#|.###.",
  7: "#####|....#|...#.|..#..|.#...|.#...|.#...",
  8: ".###.|#...#|#...#|.###.|#...#|#...#|.###.",
  9: ".###.|#...#|#...#|.####|....#|...#.|.##..",
  " ": ".....|.....|.....|.....|.....|.....|.....",
  ".": ".....|.....|.....|.....|.....|.##..|.##..",
  ",": ".....|.....|.....|.....|.##..|..#..|.#...",
  "'": "..#..|..#..|.#...|.....|.....|.....|.....",
  "?": ".###.|#...#|....#|...#.|..#..|.....|..#..",
  "!": "..#..|..#..|..#..|..#..|..#..|.....|..#..",
  "/": ".....|....#|...#.|..#..|.#...|#....|.....",
  "-": ".....|.....|.....|#####|.....|.....|.....",
  "[": ".###.|.#...|.#...|.#...|.#...|.#...|.###.",
  "]": ".###.|...#.|...#.|...#.|...#.|...#.|.###.",
  ">": ".#...|..#..|...#.|....#|...#.|..#..|.#...",
};

const EMOTES: Record<EmoteGlyph, string> = {
  "!": "..#..|..#..|..#..|.....|..#..",
  "?": ".###.|....#|..##.|.....|..#..",
  "…": ".....|.....|#.#.#|.....|.....",
  "♥": ".#.#.|#####|#####|.###.|..#..",
  "♪": "..##.|..#.#|..#..|###..|##...",
  z: "#####|...#.|..#..|.#...|#####",
  "✦": "..#..|..#..|##.##|..#..|..#..",
  "✕": "#...#|.#.#.|..#..|.#.#.|#...#",
  1: ".##..|..#..|..#..|..#..|.###.",
  2: "###..|...#.|.##..|#....|####.",
  3: "###..|...#.|.##..|...#.|###..",
};
export const EMOTE_GLYPHS = Object.keys(EMOTES) as EmoteGlyph[];
const EMOTE_INK: Record<EmoteGlyph, string> = {
  "!": "#c2553f", "?": "#6b4f9a", "…": "#4b4157", "♥": "#c0577a", "♪": "#6b4f9a",
  z: "#56779c", "✦": "#a27a23", "✕": "#c2553f", 1: "#4b4157", 2: "#4b4157", 3: "#4b4157",
};
const PAPER = "#efe6d4", OUTLINE = "#2b2433";
const ease = (value: number) => { const t = Math.max(0, Math.min(1, value)); return t * t * (3 - 2 * t); };

export const hasGlyph = (char: string) => char in FONT;
export const glyphRows = (char: string) => (FONT[char] ?? FONT[" "]).split("|");
export const textWidth = (text: string, cell: number) => text.length ? (text.length * 6 - 1) * cell : 0;

function stamp(p: PixelPainter, rows: string[], x: number, y: number, cell: number, color: string) {
  rows.forEach((row, r) => {
    let run = -1;
    for (let c = 0; c <= row.length; c++) {
      const ink = row[c] === "#";
      if (ink && run < 0) run = c;
      if (!ink && run >= 0) { p.rect(x + run * cell, y + r * cell, (c - run) * cell, cell, color); run = -1; }
    }
  });
}

export function drawText(p: PixelPainter, text: string, x: number, y: number, cell: number, color: string) {
  [...text].forEach((char, i) => stamp(p, glyphRows(char), x + i * 6 * cell, y, cell, color));
}

export function drawMark(p: PixelPainter, glyph: EmoteGlyph, x: number, y: number, cell: number, color = EMOTE_INK[glyph]) {
  stamp(p, EMOTES[glyph].split("|"), x, y, cell, color);
}

/** Chio's eyebrow mark: a lilac square with a dark shadow to its left and below. */
export function drawSeal(p: PixelPainter, x: number, y: number, cell: number, color: string) {
  p.rect(x, y + cell, cell, 4 * cell, "#5e4a72");
  p.rect(x + cell, y + 5 * cell, 4 * cell, cell, "#5e4a72");
  p.rect(x + cell, y + cell, 4 * cell, 4 * cell, color);
}

/** A pixel speech bubble. It pops up two cells, holds, and fades in its last 15%. */
export function drawEmote(ctx: CanvasRenderingContext2D, p: PixelPainter, tipX: number, tipY: number, emote: { glyph: EmoteGlyph; progress: number }, cell: number) {
  const { glyph, progress } = emote;
  if (!(progress > 0 && progress < 1)) return;
  const appear = ease(progress / .12), vanish = 1 - ease((progress - .85) / .15);
  const alpha = ctx.globalAlpha;
  ctx.globalAlpha = alpha * Math.min(appear, vanish);
  const x = tipX - 4.5 * cell, y = tipY - 11 * cell + Math.round((1 - appear) * 4) * .5 * cell;
  p.rect(x + cell, y, 7 * cell, 9 * cell, OUTLINE);
  p.rect(x, y + cell, 9 * cell, 7 * cell, OUTLINE);
  p.rect(x + cell, y + cell, 7 * cell, 7 * cell, PAPER);
  p.rect(x + 3 * cell, y + 8 * cell, 3 * cell, cell, PAPER);
  p.rect(x + 3 * cell, y + 9 * cell, 3 * cell, cell, OUTLINE);
  p.rect(x + 4 * cell, y + 9 * cell, cell, cell, PAPER);
  p.rect(x + 4 * cell, y + 10 * cell, cell, cell, OUTLINE);
  drawMark(p, glyph, x + 2 * cell, y + 2 * cell, cell);
  ctx.globalAlpha = alpha;
}
