import { SHIFT_DECK, type EmoteGlyph, type ShiftCard, type Tone } from "./workshop-deck";
import { clamp, ENTRANCE_DURATION, RELAY, smooth, WORKSHOP_CUES } from "./workshop-scene";

export type PoseName = "rest" | "ready" | "wait" | "nod" | "hmm" | "facepalm" | "leanBack" | "doze" | "startle" | "innocent";
/** The right arm and the cup run on their own track, so the body can type or react while it holds coffee. */
export type CupPose = "desk" | "grab" | "cradle" | "blow" | "sip" | "gulp" | "ahh";
export interface CupFrame { from: CupPose; to: CupPose; blend: number; held: number }
export type Beat = "rest" | "lean" | "type" | "settle" | "enter" | "gag" | "run" | "peer" | "reply" | "hold" | "out";
export type Status = "idle" | "typing" | "working" | "sealed" | "denied" | "waiting";
export interface Emote { glyph: EmoteGlyph; progress: number }
/** The fingertip travels from key `from` (-1: hovering) to `to`, arcing by `lift`, then dips by `press`. */
export interface KeyContact { from: number; to: number; travel: number; press: number; lift: number }
/** `holding`: the cup is in the operator's hand rather than on the desk. */
export interface OperatorFrame { from: PoseName; to: PoseName; blend: number; held: number; key: KeyContact | null; emote: Emote | null; sleep: number; breath: number; holding: boolean; cup: CupFrame }
export interface TerminalFrame { opacity: number; kind: "prompt" | "reply"; text: string; tone: Tone; caret: "solid" | "blink" | "none"; working: number; commit: number }
export interface JobFrame { story: number; running: boolean; bounce: boolean; carried: boolean }
export interface CrewFrame { surprise: number; wave: number; posture: number; emotes: { research?: Emote; implementation?: Emote; review?: Emote } }
export interface AlarmFrame { age: number; shake: boolean }
export interface ShiftFrame {
  t: number; card: number; cardId: string; beat: Beat;
  operator: OperatorFrame; terminal: TerminalFrame | null; job: JobFrame; crew: CrewFrame;
  alarm: AlarmFrame | null; peer: { age: number } | null; status: Status; statusAge: number;
}

export const LINE_CAPACITY = 26;
/** Keys the leaned-in operator can reach (row * 9 + column); the right edge of the console. */
export const TYPING_KEYS = [16, 25, 17, 26, 8] as const;
export const ENTER_KEY = 17;
export const BACKSPACE_KEY = 8;

const REST = 1200, FIRST_REST = 1800, LEAN = 380, SETTLE = 180, ENTER = 420, OUT = 450;
const RUN_RATE = 1.2, DOZE_RATE = .7, PEER = 2600, PRESS = .55;
const REPLY_CLEAR = 140, REPLY_CHAR = 30, HOLD_BASE = 1500, HOLD_CHAR = 40, OWNER_WAIT = 1300;
/** A cup step moves to a pose over `blend` ms, then holds it. Holds vary a little per card so no two sips keep the same time. */
type CupStep = [pose: CupPose, blend: number, hold: number];
const REACH: CupStep = ["grab", 420, 60], PUT_DOWN: CupStep[] = [["grab", 500, 60], ["desk", 420, 0]];
const SIPS: Record<"quick" | "ritual", CupStep[]> = {
  quick: [REACH, ["sip", 480, 380], ["gulp", 380, 420], ...PUT_DOWN],
  // The cup waits in front of the face, gets a cooling breath, then a long drink and a satisfied "ahh".
  ritual: [REACH, ["cradle", 560, 500], ["blow", 300, 400], ["cradle", 250, 150], ["sip", 450, 350], ["gulp", 400, 500], ["ahh", 450, 450], ...PUT_DOWN],
};
/** The hand leaves the keys once the body has settled into waiting. */
const SIP_LEAD = 520;
type Key<T> = { at: number; pose: T; blend: number };
function steps(t0: number, list: CupStep[], seed: number): Key<CupPose>[] {
  let at = t0;
  return list.map(([pose, blend, hold], i) => { const key = { at, pose, blend }; at += blend + hold * (.88 + noise(seed * 53 + i * 17) * .24); return key; });
}
/** Each key finishes arriving before the next begins, or the next would blend from a pose never reached. */
function settle<T>(keys: Key<T>[]) {
  keys.sort((a, b) => a.at - b.at);
  keys.forEach((key, i) => { const next = keys[i + 1]; if (next) key.blend = Math.max(1, Math.min(key.blend, next.at - key.at)); });
  return keys;
}

/** Deterministic hash noise in [0, 1). */
function noise(n: number) {
  let x = Math.imul(n ^ 0x9e3779b9, 0x85ebca6b);
  x ^= x >>> 13; x = Math.imul(x, 0xc2b2ae35); x ^= x >>> 16;
  return (x >>> 0) / 4294967296;
}

interface Stroke { at: number; end: number; kind: "key" | "back" | "pause"; text: string; key: number }
function strokes(script: string, pace: number, seed: number) {
  const list: Stroke[] = [];
  let text = "", at = 0;
  [...script].forEach((char, i) => {
    const kind = char === "<" ? "back" : char === "~" ? "pause" : "key";
    const base = kind === "back" ? 70 : kind === "pause" ? 420 : char === " " ? 110 : /[A-Z0-9]/.test(char) ? 72 : 140;
    const duration = kind === "pause" ? base : base * pace * (.75 + noise(seed * 977 + i * 131) * .55);
    if (kind === "back") text = text.slice(0, -1); else if (kind === "key") text += char;
    const key = kind === "back" ? BACKSPACE_KEY : kind === "pause" ? -1 : TYPING_KEYS[Math.floor(noise(seed * 31 + i * 7) * TYPING_KEYS.length)];
    list.push({ at, end: at + duration, kind, text, key });
    at += duration;
  });
  return { list, duration: at, text };
}

export interface Exchange {
  prompt: string; strokes: Stroke[]; typeAt: number; typeEnd: number; enterAt: number; enterEnd: number;
  run?: { at: number; end: number; from: number; to: number };
  peer?: [number, number]; replyAt: number; replyEnd: number; holdEnd: number; reply: string; tone: Tone; final: boolean;
}
export interface CardPlan {
  card: ShiftCard; index: number; start: number; duration: number; restEnd: number; leanEnd: number;
  gag?: [number, number]; exchanges: Exchange[]; outAt: number; startJob: { story: number; bounce: boolean };
  poses: Key<PoseName>[];
  cups: Key<CupPose>[];
  /** Loop-local window in which the cup is in hand. */
  sip?: [number, number];
}

const runs = (card: ShiftCard) => card.outcome === "seal" || card.outcome === "bounce" || card.outcome === "peer";
const gagLength = (card: ShiftCard) => card.outcome === "refuse" ? 1300 : card.outcome === "wave" ? 1800 : card.gag === "lookup" ? 1500 : card.gag === "sitUp" ? 1000 : 0;

function compile(deck: readonly ShiftCard[]): CardPlan[] {
  let clock = 0, job = { story: RELAY.end as number, bounce: false };
  return deck.map((card, index) => {
    const restEnd = index === 0 ? FIRST_REST : REST, leanEnd = restEnd + LEAN;
    const parts = card.hold
      ? [{ script: card.script, reply: card.hold.ask, tone: "waiting" as Tone, final: false }, { script: card.hold.script, reply: card.reply, tone: card.tone, final: true }]
      : [{ script: card.script, reply: card.reply, tone: card.tone, final: true }];
    const exchanges: Exchange[] = [];
    let t = leanEnd, gag: [number, number] | undefined;
    parts.forEach((part, i) => {
      const typed = strokes(part.script, card.pace ?? 1, index * 7 + i);
      const typeAt = t, typeEnd = t + typed.duration, enterAt = typeEnd + SETTLE, enterEnd = enterAt + ENTER;
      t = enterEnd;
      const g = i === 0 ? gagLength(card) : 0;
      if (g) { gag = [t, t + g]; t += g; }
      let run: Exchange["run"];
      if (runs(card)) {
        const from = i === 0 ? RELAY.start : RELAY.hold, to = card.hold && i === 0 ? RELAY.hold : RELAY.end;
        const rate = RUN_RATE * (card.gag === "doze" ? DOZE_RATE : 1);
        run = { at: t, end: t + (to - from) / rate, from, to };
        t = run.end;
      }
      let peer: Exchange["peer"];
      if (card.outcome === "peer" && part.final) { peer = [t, t + PEER]; t += PEER; }
      const replyAt = t, replyEnd = t + REPLY_CLEAR + part.reply.length * REPLY_CHAR;
      const holdEnd = replyEnd + (part.final ? HOLD_BASE + part.reply.length * HOLD_CHAR : OWNER_WAIT);
      t = holdEnd;
      exchanges.push({ prompt: typed.text, strokes: typed.list, typeAt, typeEnd, enterAt, enterEnd, run, peer, replyAt, replyEnd, holdEnd, reply: part.reply, tone: part.tone, final: part.final });
    });
    const outAt = t, duration = t + OUT, startJob = job;
    if (runs(card)) job = { story: RELAY.end, bounce: card.outcome === "bounce" };
    const poses: CardPlan["poses"] = [{ at: 0, pose: "rest", blend: 1 }, { at: restEnd, pose: "ready", blend: LEAN }];
    exchanges.forEach((exchange, i) => {
      if (card.gag === "doze" && exchange.run) poses.push({ at: exchange.enterEnd, pose: "wait", blend: 300 }, { at: exchange.run.at + 300, pose: "doze", blend: 1100 });
      else poses.push({ at: exchange.enterEnd, pose: "wait", blend: 500 });
      if (!exchange.final) {
        poses.push({ at: exchange.replyEnd, pose: "hmm", blend: 300 }, { at: exchanges[i + 1]?.typeAt ?? exchange.holdEnd, pose: "ready", blend: 250 });
      } else if (card.react === "startle") {
        poses.push({ at: exchange.replyAt, pose: "startle", blend: 90 }, { at: exchange.replyAt + 650, pose: "ready", blend: 500 });
      } else poses.push({ at: exchange.replyAt + 200, pose: card.react, blend: 380 });
    });
    const cups: Key<CupPose>[] = [{ at: 0, pose: "desk", blend: 1 }];
    const first = exchanges[0], last = exchanges[exchanges.length - 1];
    if (card.sip === "interrupted" && first.run && last !== first) {
      // Mid-drink the kernel asks the owner: the cup comes down in front of the face and stays up
      // while the left hand types Y, then a celebratory sip once the work is sealed.
      cups.push(...steps(first.run.at + SIP_LEAD, [REACH, ["sip", 480, 380], ["gulp", 380, 0]], index * 7));
      cups.push({ at: first.run.end + 60, pose: "cradle", blend: 380 });
      cups.push(...steps(last.replyAt + 200, [["sip", 450, 350], ...PUT_DOWN], index * 7 + 1));
    } else if (card.sip && first.run) {
      cups.push(...steps(first.run.at + SIP_LEAD, SIPS[card.sip === "ritual" ? "ritual" : "quick"], index * 7));
    }
    settle(cups);
    const grabs = cups.filter(key => key.pose === "grab"), lastGrab = grabs[grabs.length - 1];
    const sip: CardPlan["sip"] = grabs.length > 1 ? [grabs[0].at + grabs[0].blend, lastGrab.at + lastGrab.blend] : undefined;
    // Settle fully by the card's end so the next card starts from rest without a snap.
    poses.push({ at: outAt, pose: "rest", blend: OUT });
    settle(poses);
    const plan: CardPlan = { card, index, start: clock, duration, restEnd, leanEnd, gag, exchanges, outAt, startJob, poses, cups, sip };
    clock += duration;
    return plan;
  });
}

const PLANS = compile(SHIFT_DECK);
export const SHIFT_DURATION = PLANS.reduce((total, plan) => total + plan.duration, 0);
export const shiftPlan = (): readonly CardPlan[] => PLANS;

/** The opening cinematic ends on card one's Enter: the operator types "make no
 * mistakes" as the camera pulls back and slams Enter as it lands. */
export const ENTRANCE_HANDOFF = PLANS[0].exchanges[0].enterEnd;
/** Loop time to show at a moment of the entrance; the loop runs in real time over its last stretch. */
export const entranceShiftTime = (elapsed: number) => Math.max(0, Math.min(ENTRANCE_HANDOFF, ENTRANCE_HANDOFF - (ENTRANCE_DURATION - elapsed)));
export function cardStartById(id: string) { return PLANS.find(plan => plan.card.id === id)?.start ?? 0; }

/** Jump to the moment the next card's operator starts to lean in. */
export function skipTo(time: number) {
  const t = wrap(time), current = PLANS.findIndex(plan => t < plan.start + plan.duration);
  const next = PLANS[(current + 1) % PLANS.length];
  const base = time - t + (current + 1 === PLANS.length ? SHIFT_DURATION : 0);
  return base + next.start + next.restEnd - 150;
}

export function parseShiftQuery(search: string) {
  const match = /[?&]shift=([a-z]+)(?:@(\d+))?/.exec(search);
  if (!match || !PLANS.some(plan => plan.card.id === match[1])) return null;
  return { at: cardStartById(match[1]) + Number(match[2] ?? 0), frozen: match[2] !== undefined };
}

/** A single modulo keeps card start times exact; ((t % D) + D) % D rounds them into the previous card. */
const wrap = (time: number) => { const t = time % SHIFT_DURATION; return t < 0 ? t + SHIFT_DURATION : t; };
const window01 = (u: number, start: number, length: number) => (u - start) / length;

function beatAt(plan: CardPlan, u: number): { beat: Beat; exchange: number; since: number } {
  if (u < plan.restEnd) return { beat: "rest", exchange: 0, since: 0 };
  if (u < plan.leanEnd) return { beat: "lean", exchange: 0, since: plan.restEnd };
  for (let i = 0; i < plan.exchanges.length; i++) {
    const x = plan.exchanges[i];
    if (u < x.typeEnd) return { beat: "type", exchange: i, since: x.typeAt };
    if (u < x.enterAt) return { beat: "settle", exchange: i, since: x.typeEnd };
    if (u < x.enterEnd) return { beat: "enter", exchange: i, since: x.enterAt };
    if (i === 0 && plan.gag && u < plan.gag[1]) return { beat: "gag", exchange: i, since: plan.gag[0] };
    if (x.run && u < x.run.end) return { beat: "run", exchange: i, since: x.run.at };
    if (x.peer && u < x.peer[1]) return { beat: "peer", exchange: i, since: x.peer[0] };
    if (u < x.replyEnd) return { beat: "reply", exchange: i, since: x.replyAt };
    if (u < x.holdEnd) return { beat: "hold", exchange: i, since: x.replyEnd };
  }
  return { beat: "out", exchange: plan.exchanges.length - 1, since: plan.outAt };
}

function strokeAt(x: Exchange, u: number) {
  const local = u - x.typeAt;
  let index = -1;
  for (let i = 0; i < x.strokes.length && x.strokes[i].at <= local; i++) index = i;
  return { index, local };
}

function typedText(x: Exchange, u: number) {
  const local = u - x.typeAt;
  let text = "", lastPress = -Infinity;
  for (const stroke of x.strokes) {
    if (stroke.kind === "pause") continue;
    const press = stroke.at + (stroke.end - stroke.at) * PRESS;
    if (press > local) break;
    text = stroke.text; lastPress = press;
  }
  return { text, recent: local - lastPress < 380 };
}

function terminalAt(plan: CardPlan, u: number, beat: Beat, i: number): TerminalFrame | null {
  const opacity = Math.min(smooth((u - (plan.leanEnd - 180)) / 180), 1 - smooth((u - plan.outAt) / OUT));
  if (opacity <= 0) return null;
  const x = plan.exchanges[i], card = plan.card;
  const quiet = card.outcome === "refuse" || card.outcome === "wave";
  const pressAt = x.enterAt + ENTER * PRESS;
  const prompt = (text: string, caret: TerminalFrame["caret"], working = -1, commit = 0): TerminalFrame => ({ opacity, kind: "prompt", text, tone: x.tone, caret, working, commit });
  const reply = (text: string, caret: TerminalFrame["caret"]): TerminalFrame => ({ opacity, kind: "reply", text, tone: x.tone, caret, working: -1, commit: 0 });
  switch (beat) {
    case "rest": case "lean": return prompt("", "blink");
    case "type": { const typed = typedText(x, u); return prompt(typed.text, typed.recent ? "solid" : "blink"); }
    case "settle": return prompt(x.prompt, "solid");
    case "enter": return u < pressAt ? prompt(x.prompt, "solid") : prompt(x.prompt, "none", quiet ? -1 : u - pressAt, 1 - smooth((u - pressAt) / 260));
    case "gag": case "run": case "peer": return prompt(x.prompt, "none", quiet ? -1 : u - pressAt);
    case "reply": {
      const local = u - x.replyAt;
      if (local < REPLY_CLEAR) return prompt(x.prompt.slice(0, Math.ceil(x.prompt.length * (1 - local / REPLY_CLEAR))), "none");
      return reply(x.reply.slice(0, Math.min(x.reply.length, Math.floor((local - REPLY_CLEAR) / REPLY_CHAR) + 1)), "solid");
    }
    case "hold": return reply(x.reply, "blink");
    case "out": return reply(x.reply, "none");
  }
}

/** Where a keyframed track stands at `u`: blending from the previous key's pose into the current one. */
function track<T>(keys: Key<T>[], u: number) {
  let k = 0;
  while (k + 1 < keys.length && keys[k + 1].at <= u) k++;
  const current = keys[k], held = u - current.at;
  return { from: keys[Math.max(0, k - 1)].pose, to: current.pose, blend: k === 0 ? 1 : smooth(held / current.blend), held };
}

function operatorAt(plan: CardPlan, u: number, beat: Beat, i: number): OperatorFrame {
  const { from, to, blend, held } = track(plan.poses, u);
  const x = plan.exchanges[i], card = plan.card;
  let key: KeyContact | null = null;
  if (beat === "type") {
    const { index, local } = strokeAt(x, u);
    if (index >= 0) {
      const stroke = x.strokes[index];
      const previousKey = [...x.strokes.slice(0, index)].reverse().find(s => s.key >= 0)?.key ?? -1;
      if (stroke.kind === "pause") key = { from: previousKey, to: previousKey, travel: 1, press: 0, lift: 0 };
      else {
        const q = (local - stroke.at) / (stroke.end - stroke.at);
        key = { from: previousKey, to: stroke.key, travel: smooth(q / .45), press: Math.sin(clamp((q - .45) / .35) * Math.PI), lift: 2.5 };
      }
    }
  } else if (beat === "settle") {
    const last = [...x.strokes].reverse().find(s => s.key >= 0)?.key ?? -1;
    key = { from: last, to: ENTER_KEY, travel: smooth((u - x.typeEnd) / SETTLE), press: 0, lift: 4 };
  } else if (beat === "enter") {
    const q = (u - x.enterAt) / ENTER;
    key = { from: ENTER_KEY, to: ENTER_KEY, travel: clamp(q / .45), press: Math.sin(clamp((q - .45) / .3) * Math.PI), lift: 9 };
  }
  const last = plan.exchanges[plan.exchanges.length - 1];
  const emoteAt = last.replyAt + (card.react === "startle" ? 0 : 200);
  let emote: Emote | null = null;
  if (card.emote && u >= emoteAt && u < emoteAt + 1600) emote = { glyph: card.emote, progress: window01(u, emoteAt, 1600) };
  if (card.hold && u >= plan.exchanges[0].replyEnd && u < plan.exchanges[0].holdEnd) emote = { glyph: "…", progress: window01(u, plan.exchanges[0].replyEnd, plan.exchanges[0].holdEnd - plan.exchanges[0].replyEnd) };
  const dozing = card.gag === "doze" && x.run ? smooth((u - x.run.at - 300) / 800) * (1 - smooth((u - x.replyAt) / 120)) : 0;
  const holding = !!plan.sip && u >= plan.sip[0] && u < plan.sip[1];
  return { from, to, blend, held, key, emote, sleep: dozing, breath: plan.start + u, holding, cup: track(plan.cups, u) };
}

function crewAt(plan: CardPlan, u: number, job: JobFrame): CrewFrame {
  const card = plan.card, crew: CrewFrame = { surprise: 0, wave: 0, posture: 0, emotes: {} };
  const [gs, ge] = plan.gag ?? [0, 0];
  const inGag = !!plan.gag && u >= gs && u < ge;
  const pop = (glyph: EmoteGlyph, start: number, length: number) => u >= start && u < start + length ? { glyph, progress: window01(u, start, length) } : undefined;
  if (card.gag === "lookup" && inGag) {
    crew.surprise = smooth((u - gs) / 140) * (1 - smooth((u - (ge - 250)) / 250));
    const glyph: EmoteGlyph = u < gs + 700 ? "!" : "…";
    const start = u < gs + 700 ? gs : gs + 700, length = u < gs + 700 ? 700 : ge - gs - 700;
    crew.emotes = { research: pop(glyph, start, length), implementation: pop(glyph, start, length), review: pop(glyph, start, length) };
  }
  if (card.gag === "sitUp" && plan.gag) {
    crew.posture = smooth((u - gs) / 260) * (1 - smooth((u - plan.outAt) / 300));
    crew.emotes.implementation = pop("✦", gs, ge - gs);
  }
  if (card.gag === "steps" && job.running) {
    const s = job.story;
    const at = (from: number) => s >= from && s < from + 900 ? { glyph: "1" as EmoteGlyph, progress: (s - from) / 900 } : undefined;
    const one = at(WORKSHOP_CUES.parcelAppears), two = at(WORKSHOP_CUES.planReceived), three = at(WORKSHOP_CUES.parcelReceived);
    crew.emotes = { research: one, implementation: two && { ...two, glyph: "2" }, review: three && { ...three, glyph: "3" } };
  }
  if (card.hold) {
    const [first, second] = plan.exchanges;
    if (first.run && u >= first.run.end && u < second.enterAt) crew.emotes.review = { glyph: "?", progress: window01(u, first.run.end, second.enterAt - first.run.end) };
  }
  if (card.outcome === "bounce") {
    const hit = bounceTime(plan);
    if (hit !== null) crew.emotes.review = pop("!", hit, 800);
  }
  if (card.outcome === "refuse" && inGag) crew.emotes = { research: pop("!", gs, ge - gs), implementation: pop("!", gs + 80, ge - gs - 80), review: pop("!", gs + 160, ge - gs - 160) };
  if (card.outcome === "wave" && inGag) {
    crew.wave = smooth((u - gs) / 200) * (1 - smooth((u - (ge - 300)) / 300));
    crew.emotes = { research: pop("♥", gs, 1400), implementation: pop("♥", gs + 150, 1400), review: pop("♥", gs + 300, 1400) };
  }
  return crew;
}

function bounceTime(plan: CardPlan) {
  const run = plan.exchanges[0].run;
  return run ? run.at + (RELAY.bounce - run.from) * (run.end - run.at) / (run.to - run.from) : null;
}

function jobAt(plan: CardPlan, u: number): JobFrame {
  const { story, bounce } = plan.startJob, carried = !bounce;
  let frame: JobFrame = { story, running: false, bounce, carried };
  for (const x of plan.exchanges) {
    if (!x.run || u < x.run.at) break;
    const bounced = plan.card.outcome === "bounce";
    frame = u < x.run.end
      ? { story: x.run.from + (x.run.to - x.run.from) * (u - x.run.at) / (x.run.end - x.run.at), running: true, bounce: bounced, carried }
      : { story: x.run.to, running: false, bounce: bounced, carried };
  }
  return frame;
}

function statusAt(plan: CardPlan, u: number, beat: Beat, i: number, since: number): { status: Status; statusAge: number } {
  const x = plan.exchanges[i], card = plan.card, pressAt = x.enterAt + ENTER * PRESS;
  const toneStatus: Record<Tone, Status> = { sealed: "sealed", denied: "denied", waiting: "waiting", peered: "sealed" };
  if (beat === "rest" || beat === "out") return { status: "idle", statusAge: u - since };
  if (beat === "lean" || beat === "type" || beat === "settle" || (beat === "enter" && u < pressAt)) return { status: "typing", statusAge: u - plan.restEnd };
  if (beat === "reply" || beat === "hold") return { status: toneStatus[x.tone], statusAge: u - x.replyAt };
  if (card.outcome === "refuse") return { status: "denied", statusAge: u - pressAt };
  if (card.outcome === "wave") return { status: "sealed", statusAge: u - pressAt };
  return { status: "working", statusAge: u - pressAt };
}

export function shiftAt(time: number): ShiftFrame {
  const t = wrap(time);
  const plan = PLANS.find(card => t < card.start + card.duration) ?? PLANS[PLANS.length - 1];
  const u = t - plan.start;
  const { beat, exchange, since } = beatAt(plan, u);
  const job = jobAt(plan, u);
  const x = plan.exchanges[exchange];
  let alarm: AlarmFrame | null = null;
  if (plan.card.outcome === "bounce") {
    const hit = bounceTime(plan);
    if (hit !== null && u >= hit && u < hit + 1000) alarm = { age: u - hit, shake: false };
  }
  if (plan.card.outcome === "refuse") {
    const pressAt = plan.exchanges[0].enterAt + ENTER * PRESS;
    if (u >= pressAt && u < pressAt + 1100) alarm = { age: u - pressAt, shake: true };
  }
  const peer = x.peer && u >= x.peer[0] && u < x.peer[1] ? { age: u - x.peer[0] } : null;
  return {
    t, card: plan.index, cardId: plan.card.id, beat,
    operator: operatorAt(plan, u, beat, exchange),
    terminal: terminalAt(plan, u, beat, exchange),
    job, crew: crewAt(plan, u, job), alarm, peer,
    ...statusAt(plan, u, beat, exchange, since),
  };
}
