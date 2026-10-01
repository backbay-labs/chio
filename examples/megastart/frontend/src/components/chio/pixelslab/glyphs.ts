// 5x7 pixel letterforms on an 8-cell pitch, engraved-faceplate style. Reuses
// the exact letterforms from the shipped Playground word and adds C, E, T for
// CODE / CONNECT, and H for the THRUNT cartridge title. ▲ is the stepped
// triangle from the approved PL▲YGROUND mock: the play mark, which a label
// asks for by name (PL▲Y, RE▲DY). A is an ordinary letter.
export type Cell = [number, number, number, number]; // x, y, w, h

export const GLYPH_W = 5;
export const GLYPH_H = 7;
export const GLYPH_PITCH = 8;

export const GLYPHS: Record<string, Cell[]> = {
  P: [[0, 0, 1, 7], [1, 0, 3, 1], [4, 1, 1, 2], [1, 3, 3, 1]],
  L: [[0, 0, 1, 7], [1, 6, 4, 1]],
  A: [[1, 0, 3, 1], [0, 1, 1, 6], [4, 1, 1, 6], [1, 3, 3, 1]],
  "▲": [[2, 0, 1, 2], [1, 2, 3, 2], [0, 4, 5, 3]],
  Y: [[0, 0, 1, 2], [4, 0, 1, 2], [1, 2, 1, 1], [3, 2, 1, 1], [2, 3, 1, 4]],
  G: [[1, 0, 4, 1], [0, 1, 1, 5], [2, 3, 3, 1], [4, 4, 1, 2], [1, 6, 3, 1]],
  R: [[0, 0, 1, 7], [1, 0, 3, 1], [4, 1, 1, 2], [1, 3, 3, 1], [2, 4, 1, 1], [3, 5, 1, 1], [4, 6, 1, 1]],
  O: [[1, 0, 3, 1], [0, 1, 1, 5], [4, 1, 1, 5], [1, 6, 3, 1]],
  U: [[0, 0, 1, 6], [4, 0, 1, 6], [1, 6, 3, 1]],
  N: [[0, 0, 1, 7], [4, 0, 1, 7], [1, 1, 1, 1], [2, 2, 1, 1], [3, 3, 1, 1]],
  D: [[0, 0, 1, 7], [1, 0, 3, 1], [4, 1, 1, 5], [1, 6, 3, 1]],
  C: [[1, 0, 3, 1], [0, 1, 1, 5], [1, 6, 3, 1]],
  E: [[0, 0, 1, 7], [1, 0, 4, 1], [1, 3, 3, 1], [1, 6, 4, 1]],
  T: [[0, 0, 5, 1], [2, 1, 1, 6]],
  H: [[0, 0, 1, 7], [4, 0, 1, 7], [1, 3, 3, 1]],
  I: [[0, 0, 5, 1], [2, 1, 1, 5], [0, 6, 5, 1]],
  S: [[1, 0, 4, 1], [0, 1, 1, 2], [1, 3, 3, 1], [4, 4, 1, 2], [0, 6, 4, 1]],
  ",": [[1, 4, 2, 1], [2, 5, 1, 1], [1, 6, 1, 1]],
  "?": [[1, 0, 3, 1], [0, 1, 1, 1], [4, 1, 1, 2], [3, 3, 1, 1], [2, 4, 1, 1], [2, 6, 1, 1]],
};

export function labelCells(label: string): { char: string; cells: Cell[] }[] {
  return [...label].map((char) => {
    const cells = GLYPHS[char];
    if (!cells) throw new Error(`no engraved glyph for "${char}"`);
    return { char, cells };
  });
}
