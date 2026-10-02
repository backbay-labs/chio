import type { PixelPainter } from "./workshop-pixels";
import type { TerminalFrame } from "./workshop-shift";
import { drawSeal, drawText } from "./workshop-type";

/** The prompt bar sits under the room's foundation on the main screen, in
 * workshop units. Its right edge stops before the operator's head in the wide
 * view; it only covers the foundation's bottom tip, and only while visible. */
export const TERMINAL_BAR = { x: 8, y: 258, width: 344, height: 20 } as const;
export const TERMINAL_CELL = 2;
const PITCH = 6 * TERMINAL_CELL;
const PREFIX_X = TERMINAL_BAR.x + 6, TEXT_X = PREFIX_X + PITCH, TEXT_Y = TERMINAL_BAR.y + 3;
const INK = "#f1e7cf", DIM = "#8b7d97", RULE = "#4d3d5c";
const TONES = { sealed: "#dcc6f2", denied: "#f2ac68", waiting: "#ecd28f", peered: "#b3d8c0" } as const;

export function drawTerminal(ctx: CanvasRenderingContext2D, p: PixelPainter, frame: TerminalFrame, time: number) {
  if (!(frame.opacity > 0)) return;
  const { x, y, width, height } = TERMINAL_BAR, alpha = ctx.globalAlpha;
  const reply = frame.kind === "reply", tone = TONES[frame.tone];
  ctx.globalAlpha = alpha * frame.opacity * .94;
  p.rect(x, y, width, height, "#0b0911");
  ctx.globalAlpha = alpha * frame.opacity;
  p.rect(x, y, width, .5, reply ? tone : RULE);
  if (frame.commit > 0) {
    ctx.globalAlpha = alpha * frame.opacity * frame.commit * .28;
    p.rect(x, y, width, height, "#c9a8e8");
    ctx.globalAlpha = alpha * frame.opacity;
  }
  if (reply) drawSeal(p, PREFIX_X, TEXT_Y, TERMINAL_CELL, tone);
  else drawText(p, ">", PREFIX_X, TEXT_Y, TERMINAL_CELL, "#a58cbf");
  drawText(p, frame.text, TEXT_X, TEXT_Y, TERMINAL_CELL, reply ? tone : frame.working >= 0 ? DIM : INK);
  if (frame.caret === "solid" || (frame.caret === "blink" && Math.floor(time / 530) % 2 === 0)) {
    p.rect(TEXT_X + frame.text.length * PITCH, TEXT_Y, 5 * TERMINAL_CELL, 7 * TERMINAL_CELL, reply ? tone : INK);
  }
  if (frame.working >= 0) {
    // Three dots cycle while the workshop is busy.
    const lit = Math.floor(frame.working / 180) % 3;
    for (let i = 0; i < 3; i++) p.rect(x + width - 24 + i * 6, y + 9, 3, 3, i === lit ? TONES.sealed : RULE);
  }
  ctx.globalAlpha = alpha;
}
