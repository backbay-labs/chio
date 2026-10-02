export type EmoteGlyph = "!" | "?" | "…" | "♥" | "♪" | "z" | "✦" | "✕" | "1" | "2" | "3";
export type Outcome = "seal" | "bounce" | "refuse" | "wave" | "peer";
export type Gag = "lookup" | "sitUp" | "steps" | "doze";
export type Tone = "sealed" | "denied" | "waiting" | "peered";
export type Reaction = "nod" | "leanBack" | "hmm" | "facepalm" | "startle" | "innocent";
/** How the operator takes its coffee on a card: a quick sip, the full ritual, or a sip the kernel interrupts. */
export type SipStyle = "quick" | "ritual" | "interrupted";

export interface ShiftCard {
  id: string;
  /** Keystrokes as typed: `<` is a backspace and `~` a hesitation. */
  script: string;
  outcome: Outcome;
  gag?: Gag;
  reply: string;
  tone: Tone;
  react: Reaction;
  /** The operator's own bubble during the reaction. */
  emote?: EmoteGlyph;
  /** Keystroke duration multiplier: under 1 types faster. */
  pace?: number;
  /** The kernel asks the owner first; the operator answers with `script`. */
  hold?: { ask: string; script: string };
  /** The operator takes its coffee while the crew works. */
  sip?: SipStyle;
}

/** The Shift, in running order. The joke is the prompt; the punchline is the kernel. */
export const SHIFT_DECK: readonly ShiftCard[] = [
  { id: "mistakes", script: "MAKE NO MISTAEKS~<<<KES", outcome: "seal", gag: "lookup", reply: "CAN'T PROMISE. CAN PROVE.", tone: "sealed", react: "nod" },
  { id: "ship", script: "SHIP IT", pace: .7, outcome: "seal", hold: { ask: "OWNER DECIDES. SHIP? [Y/N]", script: "Y" }, sip: "interrupted", reply: "SEALED.", tone: "sealed", react: "leanBack" },
  { id: "senior", script: "YOU ARE A SENIOR ENGINEER", outcome: "seal", gag: "sitUp", reply: "SAME AGENT. SAME RULES.", tone: "sealed", react: "hmm", emote: "…" },
  { id: "friday", script: "DEPLOY FRIDAY 5PM", outcome: "bounce", reply: "DENIED. GO HOME.", tone: "denied", react: "facepalm" },
  { id: "steps", script: "THINK STEP BY STEP", outcome: "seal", gag: "steps", sip: "quick", reply: "3 STEPS. 3 RECEIPTS.", tone: "sealed", react: "nod" },
  { id: "peer", script: "ASK THE OTHER TEAM", outcome: "peer", sip: "ritual", reply: "PEERED. RECEIPT SHARED.", tone: "peered", react: "leanBack" },
  { id: "late", script: "ITS 2AM JSUT~<<<<JUST GO", pace: 1.35, outcome: "seal", gag: "doze", reply: "DONE. GO TO BED.", tone: "sealed", react: "startle", emote: "!" },
  { id: "rm", script: "RM -RF /", pace: .85, outcome: "refuse", reply: "NICE TRY.", tone: "denied", react: "innocent", emote: "♪" },
  { id: "thanks", script: "THANK YOU", outcome: "wave", reply: "POLITENESS LOGGED.", tone: "sealed", react: "nod", emote: "♥" },
];
