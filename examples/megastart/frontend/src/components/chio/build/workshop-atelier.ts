import { pixelPainter, type PixelPainter, type Point } from './workshop-pixels';
import type { Status } from './workshop-shift';

/** The wide shot is authored at its display scale. This aperture is also the
 * camera's exact anchor: the factory never swaps images during the pullback. */
export const ATELIER_SCREEN = { x: 123, y: 53, width: 376, height: 376 * 280 / 384, shear: -.065 };
export const ATELIER_NEIGHBORS = [
  { x: -53, y: 125, width: 164, height: 164 * 280 / 384, shear: .07 },
  { x: 534, y: 106, width: 213, height: 213 * 280 / 384, shear: -.09 },
];

type Aperture = typeof ATELIER_SCREEN;
function windowFrame(p: PixelPainter, s: Aperture, main = false) {
  const { x, y, width: w, height: h, shear } = s;
  const q = (u: number, v: number): [number, number] => [x + u, y + v + u * shear];
  p.poly([q(-9,-7),q(w+8,-7),q(w+14,-13),q(-3,-13)],main?'#665772':'#302937');
  p.poly([q(w+8,-7),q(w+14,-13),q(w+14,h+8),q(w+8,h+14)],'#231d30');
  p.poly([q(-9,-7),q(w+8,-7),q(w+8,h+14),q(-9,h+14)],main?'#3e334b':'#292332');
  p.line([q(-8,-6),q(w+7,-6)],main?'#b49abf':'#594963',1.5);
  p.line([q(-8,-6),q(-8,h+13),q(w+8,h+13)],main?'#685674':'#44384d',1);
  p.poly([q(-3,-2),q(w+2,-2),q(w+2,h+3),q(-3,h+3)],'#110e19');
  p.line([q(-3,h+3),q(w+2,h+3),q(w+2,-2)],main?'#94809f':'#584964',1);
  p.line([q(7,h+9),q(25,h+9)],main?'#b7c8ae':'#7b8a79',2);
  p.line([q(32,h+9),q(37,h+9)],'#897096',2);
  for (let i=0;i<4;i++) p.line([q(w+10,36+i*8),q(w+12,34+i*8)],'#17131e',1);
}

export function drawAtelierShell(ctx: CanvasRenderingContext2D) {
  const p=pixelPainter(ctx);
  // One quiet floor and a rear wall establish a shared, inhabited space.
  p.poly([[8,324],[349,266],[711,337],[623,480],[175,471]],'#15111c');
  p.line([[21,353],[351,293],[688,355]],'#2b2334');
  p.line([[174,471],[359,308],[623,480]],'#211a2a');
  p.line([[59,389],[653,391]],'#221b2b');
  p.line([[87,432],[628,433]],'#1e1826');
  // Architectural lintel and small recessed lights, not a star field.
  p.line([[8,88],[109,76]],'#2f2637',2);
  p.line([[521,54],[712,75]],'#302738',2);
  p.line([[35,98],[93,91]],'#8b7b91',1);
  p.line([[557,69],[603,74]],'#6c7b77',1);
  // A shallow, continuous console supports the three apertures.
  p.poly([[30,331],[550,291],[705,352],[171,424]],'#211a2d');
  p.poly([[30,331],[171,406],[705,336],[550,281]],'#66556a');
  p.poly([[33,331],[172,401],[700,334],[549,285]],'#756277');
  p.poly([[48,334],[184,394],[653,335],[541,296]],'#625269');
  p.line([[30,331],[171,406],[705,336]],'#ac8ea9',1);
  p.poly([[30,331],[171,406],[171,418],[30,344]],'#49394f');
  p.poly([[171,406],[705,336],[705,348],[171,418]],'#37283f');
  p.line([[172,407],[704,338]],'#816a88',1);
  // Recessed supports stay behind the operator; no enormous trestle feet.
  p.poly([[93,369],[116,381],[115,449],[94,440]],'#302737');
  p.poly([[629,358],[650,356],[648,440],[629,443]],'#251d30');
  p.line([[94,386],[94,437]],'#54445f',1);
  // Main terminal stem and base belong to the same screen plane.
  p.poly([[277,298],[318,293],[319,332],[282,338]],'#42364f');
  p.line([[280,299],[284,333]],'#786485',2);
  p.poly([[258,335],[298,322],[344,334],[303,349]],'#3e334b','#86718e');
  for (const s of ATELIER_NEIGHBORS) windowFrame(p,s);
  windowFrame(p,ATELIER_SCREEN,true);
  // A deliberately small control surface, angled into the work.
  p.poly([[337,341],[428,328],[466,346],[370,361]],'#302638','#95809f');
  p.poly([[347,341],[425,332],[452,345],[372,356]],'#51435e');
  for(let row=0;row<3;row++) for(let col=0;col<9;col++) {
    const x=356+col*7+row*6,y=341-col*.9+row*4;
    p.poly([[x,y],[x+5,y-.7],[x+8,y+.8],[x+3,y+1.6]],(row+col)%5===0?'#96aca2':'#a294af');
  }
  // Note card and a single ceramic cup give scale without clutter.
  p.poly([[211,354],[243,348],[262,359],[229,366]],'#c5bda9');
  p.line([[223,355],[244,353]],'#79877f',1);
  p.line([[227,359],[240,357]],'#948880',1);
  p.ellipse(184,348,10,4,'#302836');
  p.rect(175,331,16,15,'#859c90');p.rect(176,332,3,13,'#bccabb');
  p.ellipse(183,331,8,3,'#cdd6bf');p.ellipse(183,331,5.5,1.5,'#332f36');
  p.line([[191,334],[198,333],[198,342],[192,344]],'#a3b4a3',2);
  // A quiet cable follows the edge and terminates at a visible socket.
  p.line([[496,344],[517,352],[516,371],[544,382]],'#302735',2);
  p.rect(540,379,10,5,'#806b8b');
}

/** A pressed console key sinks half a unit and brightens under the fingertip. */
export function drawKeyPress(p: PixelPainter, id: number, press: number) {
  if (id < 0 || press <= .05) return;
  const row = Math.floor(id / 9), col = id % 9, x = 356 + col * 7 + row * 6, y = 341 - col * .9 + row * 4 + .5;
  p.poly([[x,y],[x+5,y-.7],[x+8,y+.8],[x+3,y+1.6]], press > .5 ? '#f3e6fb' : '#cbb9d9');
}

const STATUS_INK: Record<Status, string> = { idle: '#b7c8ae', typing: '#e6cf8c', working: '#e6cf8c', sealed: '#d8c0f0', denied: '#f0a061', waiting: '#e6cf8c' };
/** The main terminal's bezel light reports the shift's state. */
export function drawStatusLight(p: PixelPainter, status: Status, age: number) {
  const on = status === 'working' ? Math.floor(age / 260) % 2 === 0
    : status === 'denied' ? Math.floor(age / 140) % 2 === 0
    : status === 'waiting' ? Math.floor(age / 600) % 2 === 0 : true;
  const ink = status === 'sealed' && age > 1400 ? STATUS_INK.idle : STATUS_INK[status];
  p.line([[130,335.7],[148,334.5]], on ? ink : '#4c5a49', 2);
}

/** The operator's own cup sits at its right hand, handle toward it; the older
 * green mug on the far left belongs to someone else. Body center, world units. */
export const CUP_ON_DESK: Point = [591, 327];
/** Where the fingers close on the handle, in the cup's own upright frame. */
export const CUP_GRIP: Point = [-10.5, -.5];

/** A lilac cup around `center`, turned by `angle` (0 upright, a quarter turn
 * clockwise lays it on its side with the rim to the right). `mirror` puts the
 * handle on the right: toward the operator once the cup is at its face. */
export function drawCup(p: PixelPainter, center: Point, angle: number, onDesk: boolean, mirror = false) {
  const c = Math.cos(angle), s = Math.sin(angle);
  const at = ([x, y]: Point): Point => { const u = mirror ? -x : x; return [center[0] + u * c - y * s, center[1] + u * s + y * c]; };
  const oval = (cy: number, rx: number, ry: number) => Array.from({ length: 12 }, (_, i): Point => at([Math.cos(i * Math.PI / 6) * rx, cy + Math.sin(i * Math.PI / 6) * ry]));
  if (onDesk) p.ellipse(center[0] + .5, center[1] + 7.5, 8, 3, '#302836');
  p.line(([[-6.5, -3.5], [-10.5, -4], [-10.5, 3], [-6.5, 4]] as Point[]).map(at), '#b9a5cc', 1.5);
  p.poly(([[-6.5, -6], [6.5, -6], [6.5, 6], [-6.5, 6]] as Point[]).map(at), '#9d88b3');
  p.poly(([[-5.5, -5], [-4, -5], [-4, 5], [-5.5, 5]] as Point[]).map(at), '#cbb8dc');
  p.poly(oval(-6, 6.5, 2.4), '#e2d4ee');
  p.poly(oval(-6, 4.4, 1.2), '#332f36');
}

/** Three wisps rise from the operator's cup and fade. */
export function drawSteam(ctx: CanvasRenderingContext2D, p: PixelPainter, time: number) {
  const alpha = ctx.globalAlpha, [x, y] = CUP_ON_DESK;
  for (let i = 0; i < 3; i++) {
    const rise = ((time + i * 800) % 2400) / 2400;
    ctx.globalAlpha = alpha * .45 * Math.sin(rise * Math.PI);
    p.rect(x - 3 + i * 2.5 + Math.round(Math.sin(rise * 6 + i) * 2) * .5, y - 9 - rise * 18, 1, 1.5, '#e4dcea');
  }
  ctx.globalAlpha = alpha;
}

/** Work in flight between terminals: a haloed pixel head and a stepped trail on one arc. */
export function drawComet(ctx: CanvasRenderingContext2D, p: PixelPainter, from: [number, number], to: [number, number], u: number, palette: readonly string[]) {
  const c: [number, number] = [(from[0] + to[0]) / 2, Math.min(from[1], to[1]) - 70];
  const at = (s: number): [number, number] => { const a = 1 - s; return [a*a*from[0] + 2*a*s*c[0] + s*s*to[0], a*a*from[1] + 2*a*s*c[1] + s*s*to[1]]; };
  const [hx, hy] = at(Math.max(0, Math.min(1, u))), alpha = ctx.globalAlpha;
  for (let ring = 3; ring > 0; ring--) {
    ctx.globalAlpha = alpha * (4 - ring) * .07;
    p.ellipse(hx, hy, ring * 4, ring * 3, palette[0]);
  }
  ctx.globalAlpha = alpha;
  for (let i = palette.length - 1; i >= 0; i--) {
    const s = u - i * .028;
    if (s < 0 || s > 1) continue;
    const [x, y] = at(s), size = Math.max(1, 6 - i);
    p.rect(Math.round(x - size / 2), Math.round(y - size / 2), size, size, palette[i]);
  }
}

/** A soft bloom of concentric pixel ellipses where peered work lands. */
export function drawBloom(ctx: CanvasRenderingContext2D, p: PixelPainter, at: [number, number], amount: number) {
  if (amount <= 0) return;
  const alpha = ctx.globalAlpha;
  for (let ring = 4; ring > 0; ring--) {
    ctx.globalAlpha = alpha * amount * (5 - ring) * .06;
    p.ellipse(at[0], at[1], ring * 6, ring * 2.6, '#cfe7d7');
  }
  ctx.globalAlpha = alpha;
}
