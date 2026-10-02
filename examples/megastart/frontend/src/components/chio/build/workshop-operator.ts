import { pixelPainter, type PixelPainter, type Point } from "./workshop-pixels";
import { ENTER_KEY, type CupPose, type Emote, type OperatorFrame, type PoseName } from "./workshop-shift";
import { drawEmote, drawMark } from "./workshop-type";
import { CUP_GRIP, CUP_ON_DESK, drawCup } from "./workshop-atelier";

export interface OperatorPose {
  /** Torso bend toward the screen, radians about the hip. */
  lean: number;
  /** Chin up (positive) or down, radians about the neck. */
  headTilt: number;
  headX: number; headY: number;
  /** Wrist target in world units; the arm is solved to reach it. */
  wrist: Point;
  /** 1 open, 0 closed, above 1.15 wide. */
  eyes: number;
  antenna: number;
  foot: number;
  /** Idle breathing bob, in world units. */
  bob: number;
  /** The right arm lives behind the torso (0) until it reaches for the cup (1). */
  reach: number;
  /** Right elbow and hand, world units; seen from behind, the forearm crosses behind the head to drink. */
  rElbow: Point;
  rHand: Point;
  /** Cup tilt in radians while held: 0 upright, about a quarter turn at the visor. */
  cup: number;
  /** Above .5 the cup is drawn mirrored, handle toward the face. */
  flip: number;
  /** Steam rising from the cup in hand, and how hard it is being blown. */
  steam: number;
  blow: number;
}

/** Today's seated pose: drawing it reproduces the original operator exactly. */
export const NEUTRAL_POSE: OperatorPose = { lean: 0, headTilt: 0, headX: 0, headY: 0, wrist: [437, 352], eyes: 1, antenna: 0, foot: 0, bob: 0, reach: 0, rElbow: [538, 382], rHand: [532, 398], cup: 0, flip: 0, steam: 0, blow: 0 };

const HIP: Point = [517, 420], NECK: Point = [509, 338], SHOULDER: Point = [487, 351], ELBOW: Point = [461, 365];
/** The right shoulder sits under the torso's top-right corner. */
const RIGHT_SHOULDER: Point = [552, 351];
export const UPPER_ARM = Math.hypot(ELBOW[0] - SHOULDER[0], ELBOW[1] - SHOULDER[1]);
export const FOREARM = Math.hypot(NEUTRAL_POSE.wrist[0] - ELBOW[0], NEUTRAL_POSE.wrist[1] - ELBOW[1]);

/** Console key geometry from the atelier shell (row * 9 + column). */
export const keyCenter = (id: number): Point => { const row = Math.floor(id / 9), col = id % 9; return [360 + col * 7 + row * 6, 341.5 - col * .9 + row * 4]; };
/** The fingertip sits six units left of and three above the wrist. */
export const keyWrist = (id: number): Point => { const [x, y] = keyCenter(id); return [x + 6, y + 3]; };

const READY = keyWrist(ENTER_KEY);
/** The right hand's grip on the cup's handle while the cup sits on the desk. */
export const MUG_GRIP: Point = [CUP_ON_DESK[0] + CUP_GRIP[0], CUP_ON_DESK[1] + CUP_GRIP[1]];
export const POSES: Record<PoseName, OperatorPose> = {
  rest: NEUTRAL_POSE,
  ready: { ...NEUTRAL_POSE, lean: .2, headTilt: .09, wrist: READY },
  wait: { ...NEUTRAL_POSE, lean: .05, headTilt: .03, wrist: [442, 355] },
  nod: { ...NEUTRAL_POSE, lean: .12, headTilt: .04, wrist: [443, 356] },
  hmm: { ...NEUTRAL_POSE, lean: .02, headTilt: .07, headX: 1.5, wrist: [447, 360] },
  facepalm: { ...NEUTRAL_POSE, lean: .1, headTilt: -.14, headY: 1, wrist: [481, 318] },
  leanBack: { ...NEUTRAL_POSE, lean: -.08, headTilt: .1, wrist: [452, 362] },
  doze: { ...NEUTRAL_POSE, lean: -.04, headTilt: -.3, headY: 3, eyes: 0, wrist: [463, 391] },
  startle: { ...NEUTRAL_POSE, lean: -.05, headTilt: .12, headY: -5, eyes: 1.3, antenna: 1, wrist: [446, 350] },
  innocent: { ...NEUTRAL_POSE, lean: -.1, headTilt: .16, headX: 1, wrist: [455, 364] },
};

/** The cup track: the right arm, the cup, and the head's small reactions to
 * drinking. Face poses hold the hand in head space and the elbow in torso space,
 * so the cup stays at the face whatever the body is doing. */
interface CupPreset { reach: number; elbow: Point; hand: Point; atFace: boolean; cup: number; flip: number; tilt: number; lean: number; antenna: number; steam: number; blow: number }
const DESK: CupPreset = { reach: 0, elbow: NEUTRAL_POSE.rElbow, hand: NEUTRAL_POSE.rHand, atFace: false, cup: 0, flip: 0, tilt: 0, lean: 0, antenna: 0, steam: 0, blow: 0 };
const CRADLE: CupPreset = { ...DESK, reach: 1, elbow: [568, 342], hand: [476.5, 323.5], atFace: true, flip: 1, tilt: -.05, steam: 1 };
export const CUP_POSES: Record<CupPose, CupPreset> = {
  desk: DESK,
  // The right hand takes the cup by its handle; the left stays with the body.
  grab: { ...DESK, reach: 1, elbow: [575, 353], hand: MUG_GRIP },
  // Upright just below the visor, head dipped as if looking into it.
  cradle: CRADLE,
  blow: { ...CRADLE, elbow: [568, 340], hand: [478, 321], tilt: -.09, blow: 1 },
  // Seen from behind: elbow out, forearm behind the head, the rim at the visor.
  sip: { ...DESK, reach: 1, elbow: [571, 334], hand: [476.9, 321.9], atFace: true, cup: 1.1, flip: 1, tilt: .12, lean: -.04 },
  gulp: { ...DESK, reach: 1, elbow: [572, 328], hand: [469.7, 317.3], atFace: true, cup: 1.75, flip: 1, tilt: .2, lean: -.07 },
  ahh: { ...CRADLE, tilt: .1, antenna: 1, steam: .5 },
};

/** Procedural motion layered on the pose the operator is moving into. */
function perform(name: PoseName, held: number): OperatorPose {
  const base = POSES[name];
  if (name === "nod") return { ...base, headTilt: base.headTilt - .15 * Math.max(0, Math.sin(Math.min(held, 1040) / 260 * Math.PI)) };
  if (name === "wait") {
    const drum = held % 1500 < 420 ? (Math.floor(held / 70) % 2) * .8 : 0;
    return { ...base, wrist: [base.wrist[0], base.wrist[1] - drum], foot: held % 900 < 160 ? 1 : 0 };
  }
  if (name === "facepalm") return { ...base, headX: held < 900 ? Math.sin(held / 70) * .6 : 0 };
  if (name === "doze") return { ...base, headTilt: base.headTilt + Math.sin(held / 1300) * .03 };
  return base;
}

function mixPose(a: OperatorPose, b: OperatorPose, t: number): OperatorPose {
  const m = (x: number, y: number) => t >= 1 ? y : t <= 0 ? x : x + (y - x) * t;
  return {
    lean: m(a.lean, b.lean), headTilt: m(a.headTilt, b.headTilt), headX: m(a.headX, b.headX), headY: m(a.headY, b.headY),
    wrist: [m(a.wrist[0], b.wrist[0]), m(a.wrist[1], b.wrist[1])], eyes: m(a.eyes, b.eyes), antenna: m(a.antenna, b.antenna),
    foot: m(a.foot, b.foot), bob: m(a.bob, b.bob), reach: m(a.reach, b.reach),
    rElbow: [m(a.rElbow[0], b.rElbow[0]), m(a.rElbow[1], b.rElbow[1])], rHand: [m(a.rHand[0], b.rHand[0]), m(a.rHand[1], b.rHand[1])], cup: m(a.cup, b.cup),
    flip: m(a.flip, b.flip), steam: m(a.steam, b.steam), blow: m(a.blow, b.blow),
  };
}

export function operatorPose(frame: OperatorFrame): OperatorPose {
  const pose = mixPose(POSES[frame.from], perform(frame.to, frame.held), frame.blend);
  if (frame.key) {
    const { from, to, travel, press, lift } = frame.key;
    // The first stroke leaves from wherever the pose has the hand, never a fixed hover point.
    const a = from < 0 ? pose.wrist : keyWrist(from), b = to < 0 ? a : keyWrist(to);
    pose.wrist = [a[0] + (b[0] - a[0]) * travel, a[1] + (b[1] - a[1]) * travel - Math.sin(travel * Math.PI) * lift + press * 1.6];
  }
  // A one-pixel breath and a blink every few seconds; both are still at loop time zero.
  pose.bob = Math.sin(frame.breath / 1700 * Math.PI * 2) > .55 ? .5 : 0;
  if (frame.breath % 4300 > 4180) pose.eyes = 0;
  // The cup track layers on top of the body.
  const a = CUP_POSES[frame.cup.from], b = CUP_POSES[frame.cup.to], t = frame.cup.blend;
  const m = (x: number, y: number) => t >= 1 ? y : t <= 0 ? x : x + (y - x) * t;
  pose.headTilt += m(a.tilt, b.tilt); pose.lean += m(a.lean, b.lean);
  pose.antenna = Math.max(pose.antenna, m(a.antenna, b.antenna));
  const torso = torsoOf(pose), head = headOf(pose);
  const place = (preset: CupPreset) => preset.atFace ? { elbow: torso?.(preset.elbow) ?? preset.elbow, hand: head?.(preset.hand) ?? preset.hand } : preset;
  const pa = place(a), pb = place(b);
  pose.reach = m(a.reach, b.reach); pose.cup = m(a.cup, b.cup); pose.steam = m(a.steam, b.steam); pose.blow = m(a.blow, b.blow);
  pose.rElbow = [m(pa.elbow[0], pb.elbow[0]), m(pa.elbow[1], pb.elbow[1])];
  pose.rHand = [m(pa.hand[0], pb.hand[0]), m(pa.hand[1], pb.hand[1])];
  // The handle turns toward the face while the cup passes behind the head.
  pose.flip = t < .5 ? a.flip : b.flip;
  return pose;
}

/** Where the held cup's body sits for a pose: the hand holds the handle. */
function cupCenter(pose: OperatorPose): Point {
  const c = Math.cos(pose.cup), s = Math.sin(pose.cup), gx = pose.flip > .5 ? -CUP_GRIP[0] : CUP_GRIP[0], gy = CUP_GRIP[1];
  return [pose.rHand[0] - (gx * c - gy * s), pose.rHand[1] - (gx * s + gy * c)];
}

type Xf = ((point: Point) => Point) | null;
const turn = (pivot: Point, angle: number, dx = 0, dy = 0): Xf => !angle && !dx && !dy ? null : ([x, y]) => {
  const c = Math.cos(angle), s = Math.sin(angle), u = x - pivot[0], v = y - pivot[1];
  return [pivot[0] + u * c - v * s + dx, pivot[1] + u * s + v * c + dy];
};
const then = (first: Xf, second: Xf): Xf => !first ? second : !second ? first : point => second(first(point));
const torsoOf = (pose: OperatorPose) => turn(HIP, -pose.lean, 0, pose.bob);
const headOf = (pose: OperatorPose) => then(turn(NECK, pose.headTilt), then(torsoOf(pose), turn([0, 0], 0, pose.headX, pose.headY)));
export const shoulderFor = (pose: OperatorPose): Point => torsoOf(pose)?.(SHOULDER) ?? SHOULDER;

/** Identity transforms keep today's exact draw calls, rects included. */
function posed(p: PixelPainter, xf: Xf) {
  const map = (points: Point[]) => xf ? points.map(xf) : points;
  return {
    poly: (points: Point[], fill: string) => p.poly(map(points), fill),
    line: (points: Point[], color: string, width?: number) => p.line(map(points), color, width),
    rect: (x: number, y: number, w: number, h: number, color: string) => xf ? p.poly(map([[x,y],[x+w,y],[x+w,y+h],[x,y+h]]), color) : p.rect(x, y, w, h, color),
  };
}

/** Two-bone arm. The elbow always bends to the same side of the shoulder-wrist
 * line, like a real joint: below it while typing, forward when the hand rises. */
export function solveArm(shoulder: Point, target: Point): { elbow: Point; wrist: Point } {
  const dx = target[0] - shoulder[0], dy = target[1] - shoulder[1], reach = Math.hypot(dx, dy);
  const ux = reach > 1e-6 ? dx / reach : -1, uy = reach > 1e-6 ? dy / reach : 0;
  const d = Math.max(Math.abs(UPPER_ARM - FOREARM) + .01, Math.min(UPPER_ARM + FOREARM - .01, reach));
  const wrist: Point = reach === d ? target : [shoulder[0] + ux * d, shoulder[1] + uy * d];
  const bend = Math.acos(Math.max(-1, Math.min(1, (UPPER_ARM * UPPER_ARM + d * d - FOREARM * FOREARM) / (2 * UPPER_ARM * d))));
  const base = Math.atan2(uy, ux);
  const elbows = [base + bend, base - bend].map(a => [shoulder[0] + UPPER_ARM * Math.cos(a), shoulder[1] + UPPER_ARM * Math.sin(a)] as Point);
  const side = (e: Point) => ux * (e[1] - shoulder[1]) - uy * (e[0] - shoulder[0]);
  return { elbow: side(elbows[0]) < side(elbows[1]) ? elbows[0] : elbows[1], wrist };
}

// The original arm art is bound to the bones of today's pose and re-placed per frame.
type Bone = "upper" | "fore" | "hand";
interface Frame { o: Point; u: Point; n: Point }
const frameOf = (a: Point, b: Point): Frame => { const l = Math.hypot(b[0] - a[0], b[1] - a[1]) || 1; const u: Point = [(b[0] - a[0]) / l, (b[1] - a[1]) / l]; return { o: a, u, n: [-u[1], u[0]] }; };
const round = (n: number) => Math.round(n * 1e6) / 1e6;
const BIND: Record<Bone, Frame> = (() => { const upper = frameOf(SHOULDER, ELBOW), fore = frameOf(ELBOW, NEUTRAL_POSE.wrist); return { upper, fore, hand: { ...fore, o: NEUTRAL_POSE.wrist } }; })();
const skin = (points: [number, number, Bone][]) => points.map(([x, y, bone]) => { const f = BIND[bone], dx = x - f.o[0], dy = y - f.o[1]; return { bone, a: dx * f.u[0] + dy * f.u[1], c: dx * f.n[0] + dy * f.n[1] }; });
const ARM = skin([[490,350,"upper"],[472,348,"upper"],[459,359,"upper"],[440,350,"fore"],[433,355,"fore"],[460,372,"upper"],[480,365,"upper"]]);
const ARM_LINE = skin([[487,351,"upper"],[472,353,"upper"],[461,365,"fore"],[439,353,"fore"]]);
const HAND = skin([[431,349,"hand"],[441,347,"hand"],[448,352,"hand"],[442,358,"hand"],[434,356,"hand"]]);
function placeArm(shoulder: Point, elbow: Point, wrist: Point) {
  const fore = frameOf(elbow, wrist), frames: Record<Bone, Frame> = { upper: frameOf(shoulder, elbow), fore, hand: { ...fore, o: wrist } };
  const place = (list: ReturnType<typeof skin>) => list.map(({ bone, a, c }): Point => { const f = frames[bone]; return [round(f.o[0] + f.u[0] * a + f.n[0] * c), round(f.o[1] + f.u[1] * a + f.n[1] * c)]; });
  return { arm: place(ARM), line: place(ARM_LINE), hand: place(HAND) };
}

/** Two tapered quads and a round elbow: the right arm is simpler art than the
 * left because it only appears for a moment, mostly in shadow. */
function drawRightArm(p: PixelPainter, shoulder: Point, elbow: Point, hand: Point) {
  const band = (a: Point, b: Point, ta: number, tb: number): Point[] => {
    const l = Math.hypot(b[0] - a[0], b[1] - a[1]) || 1, nx = -(b[1] - a[1]) / l, ny = (b[0] - a[0]) / l;
    return [[a[0] + nx * ta, a[1] + ny * ta], [b[0] + nx * tb, b[1] + ny * tb], [b[0] - nx * tb, b[1] - ny * tb], [a[0] - nx * ta, a[1] - ny * ta]];
  };
  p.poly(band(shoulder, elbow, 6.5, 5), '#5c7467');
  p.poly(band(elbow, hand, 5, 3.6), '#5c7467');
  p.ellipse(elbow[0], elbow[1], 5, 5, '#5c7467');
  p.line([[shoulder[0], shoulder[1] - 4.5], [elbow[0], elbow[1] - 4]], '#8ea38e', 2);
}

/** The right hand, closing on the cup's handle when it holds the cup. */
function drawRightHand(p: PixelPainter, pose: OperatorPose, holding: boolean) {
  const [x, y] = pose.rHand;
  if (holding) drawCup(p, cupCenter(pose), pose.cup, false, pose.flip > .5);
  p.poly([[x - 4, y - 3.5], [x + 3.5, y - 4.5], [x + 6, y + .5], [x + 2, y + 4.5], [x - 4, y + 3.5]], '#a8b99f');
}

/** Seated, three-quarter rear silhouette: the head turns into the factory.
 * Hands are in front of the torso and land on the console's control plane. */
export function drawOperator(ctx: CanvasRenderingContext2D, pose: OperatorPose, acknowledge: number, holding = false) {
  const p = pixelPainter(ctx), light = acknowledge > .35 || pose.antenna > .5;
  const torso = posed(p, torsoOf(pose)), head = posed(p, headOf(pose));
  const foot = posed(p, pose.foot ? turn([0, 0], 0, 0, -pose.foot * 1.5) : null);
  const shoulder = shoulderFor(pose);
  const { elbow, wrist } = solveArm(shoulder, pose.wrist);
  const arm = placeArm(shoulder, elbow, wrist);
  // A hand raised to the face is drawn in front of the head.
  const raised = wrist[1] < shoulder[1] - 8;
  p.ellipse(519,467,76,15,'#0c0b12');
  // Feet and knees beneath the chair.
  p.poly([[470,420],[486,423],[480,456],[463,454]],'#494252');
  p.poly([[458,448],[482,451],[490,461],[462,463],[451,458]],'#877d92');
  p.line([[455,451],[478,454]],'#b1a1b9',1);
  p.poly([[526,424],[542,423],[545,456],[529,459]],'#36303f');
  foot.poly([[527,456],[545,453],[558,462],[551,469],[527,466]],'#665a76');
  // Far upper arm, elbow and wrist reach toward the keyboard.
  if (!raised) {
    p.poly(arm.arm,'#6e8a7d');
    p.line(arm.line,'#afc2a7',3);
    p.poly(arm.hand,'#bdccb4');
  } else {
    p.poly([arm.arm[0],arm.arm[1],arm.arm[2],arm.arm[5],arm.arm[6]],'#6e8a7d');
    p.line(arm.line.slice(0,3),'#afc2a7',3);
  }
  // The right arm comes out from behind the torso; a hand at the face is drawn after the head.
  const rightShoulder = torsoOf(pose)?.(RIGHT_SHOULDER) ?? RIGHT_SHOULDER, atFace = pose.rHand[0] < 500;
  if (pose.reach > .01) {
    drawRightArm(p, rightShoulder, pose.rElbow, pose.rHand);
    if (!atFace) drawRightHand(p, pose, holding);
  }
  // Torso faces the terminal, back panel toward the viewer.
  torso.poly([[489,344],[535,337],[560,356],[555,410],[527,427],[479,407]],'#809283');
  torso.poly([[535,337],[560,356],[555,410],[535,419]],'#475d56');
  torso.poly([[489,351],[531,346],[547,359],[543,403],[523,414],[486,400]],'#637b6b');
  torso.line([[489,348],[534,341],[555,356]],'#b3c0a8',2);
  torso.poly([[505,366],[527,362],[535,368],[532,391],[509,396]],'#36483f');
  torso.line([[512,373],[526,370],[526,386],[513,389]],'#839885',2);
  torso.line([[513,379],[521,377]],'#bfd0af',2);
  // Neck and head: the narrow visible face is on the screen-facing side.
  torso.rect(499,329,20,16,'#3e5149');
  head.poly([[475,285],[513,272],[546,288],[507,302]],'#c4ceb8');
  head.poly([[507,302],[546,288],[545,328],[509,343]],'#789181');
  head.poly([[475,285],[507,302],[509,343],[478,325]],'#91a88f');
  head.line([[475,285],[508,300],[545,287]],'#e0e4c9',2);
  head.poly([[474,295],[488,302],[490,327],[477,320]],'#222c32');
  if (pose.eyes < .5) head.line([[477,306],[482,309]],'#e2e8c9',1);
  else if (pose.eyes > 1.15) head.poly([[476,300],[483,303.5],[483,313],[476,309.5]],light?'#fff0ce':'#f4f6df');
  else head.poly([[477,302],[482,305],[482,311],[477,308]],light?'#fff0ce':'#e2e8c9');
  head.line([[476,321],[490,328]],'#c2d3b1',1);
  head.rect(526,303,4,14,'#526d61');head.rect(526,303,4,3,'#a9bda2');
  head.line([[500,278],[500,265]],'#819482',3);
  head.rect(495,261,11,5,light?'#f1e5b6':'#b4c1a7');
  if (pose.reach > .01 && atFace) drawRightHand(p, pose, holding);
  if (raised) {
    p.poly([arm.arm[2],arm.arm[3],arm.arm[4],arm.arm[5]],'#6e8a7d');
    p.line(arm.line.slice(2),'#afc2a7',3);
    p.poly(arm.hand,'#bdccb4');
  }
  // Low-backed chair grounds the seated figure without obscuring its pose.
  p.poly([[491,416],[555,401],[571,411],[569,451],[508,469],[491,455]],'#352c43');
  p.poly([[499,421],[558,407],[563,412],[561,443],[509,458],[500,451]],'#554862');
  p.line([[498,420],[559,405],[570,411]],'#887296',2);
  p.line([[527,463],[527,478],[501,484]],'#413649',3);
  p.line([[527,478],[558,482]],'#413649',3);
}

/** Speech bubble above the antenna, or three z's drifting up while asleep. */
export function drawOperatorMarks(ctx: CanvasRenderingContext2D, pose: OperatorPose, emote: Emote | null, sleep: number, time: number) {
  if (!emote && !(sleep > 0) && !(pose.steam > .2)) return;
  const p = pixelPainter(ctx), xf = headOf(pose);
  if (pose.steam > .2) {
    // Steam off the cup in hand; a breath pushes it away from the face.
    const [cx, cy] = cupCenter(pose), alpha = ctx.globalAlpha;
    for (let i = 0; i < 3; i++) {
      const age = ((time + i * 500) % 1500) / 1500;
      ctx.globalAlpha = alpha * pose.steam * .5 * Math.sin(age * Math.PI);
      p.rect(Math.round((cx - 2 + i * 2 - pose.blow * age * 10 + Math.sin(age * 6 + i)) * 2) / 2, cy - 8 - age * 12, 1, 1.5, '#e4dcea');
    }
    ctx.globalAlpha = alpha;
  }
  const [ax, ay] = xf ? xf([489, 259]) : [489, 259];
  if (emote) drawEmote(ctx, p, ax, ay, emote, 2);
  if (sleep > 0) {
    const alpha = ctx.globalAlpha;
    for (let i = 0; i < 3; i++) {
      const age = ((time + i * 700) % 2100) / 2100;
      ctx.globalAlpha = alpha * sleep * Math.sin(age * Math.PI);
      drawMark(p, "z", Math.round(ax - 4 + age * 16), Math.round(ay - 4 - age * 26), [1, 1.5, 2][Math.min(2, Math.floor(age * 3))], "#c9d6e8");
    }
    ctx.globalAlpha = alpha;
  }
}

/** Pointer target for the seated operator in world units (head, torso, chair). */
export const operatorAt = (x: number, y: number) => x >= 470 && x <= 575 && y >= 255 && y <= 485;
