import { labelCells, GLYPH_PITCH } from "../pixelslab/glyphs";
import { pixelPainter, WORKSHOP_PIXEL_SCALE, type Point } from "./workshop-pixels";
import { drawStation } from "./workshop-station";
import { drawCartridge } from "./workshop-cartridge";
import { drawEmote } from "./workshop-type";
import { drawTerminal } from "./workshop-terminal";
import type { AlarmFrame, CrewFrame, JobFrame, TerminalFrame } from "./workshop-shift";

export { WORKSHOP_PIXEL_SCALE } from "./workshop-pixels";

export const ROLES = [
  { id: "research", name: "Research", number: "01", verb: "Find what’s broken.", description: "Inspect the source and reproduce the failures caused by empty windows and integer overflow.", artifact: "Source + test harness", agent: "hermes", agentName: "Hermes" },
  { id: "implementation", name: "Implementation", number: "02", verb: "Compare two repairs.", description: "Retain both candidates. The host tests each repair against the original harness; workers cannot change its tests.", artifact: "Candidate source + tests", agent: "codex", agentName: "Codex" },
  { id: "review", name: "Review", number: "03", verb: "Review the candidate.", description: "Evaluate the selected repair and its test results. Publication requires the owner’s decision.", artifact: "Review + owner decision", agent: "pi", agentName: "Pi" },
] as const;
export type Role = typeof ROLES[number]["id"];

const chio = labelCells("CHIO");
const stations: { role: Role; x: number; y: number; color: string }[] = [
  { role: "research", x: 111, y: 119, color: "#b4c8bb" },
  { role: "review", x: 262, y: 119, color: "#d8bc8e" },
  { role: "implementation", x: 187, y: 160, color: "#ccb0ed" },
];

/** Pointer equivalent of the labelled role controls below the illustration. */
export function workshopRoleAt(x: number, y: number): Role | null {
  return [...stations].reverse().find(station => x >= station.x-35 && x <= station.x+35 && y >= station.y-37 && y <= station.y+43)?.role ?? null;
}

export const WORKSHOP_WIDTH = 384;
export const WORKSHOP_HEIGHT = 280;
/** One clock for the acting, camera, parcel, and typography. Holds are real
 * camera rests; the workshop continues moving throughout them. */
export const WORKSHOP_CUES = {
  firstTitle: 380,
  parcelAppears: 900,
  glance: 1430,
  pullback: 1700,
  handoff: 1900,
  planReceived: 2280,
  assembled: 2670,
  builderRelease: 2860,
  parcelReceived: 3230,
  sealed: 3570,
  dispatch: 3790,
  docked: 4120,
  powered: 4390,
  secondTitle: 2900,
  wide: 3500,
  recurse: 5400,
  outerWide: 6900,
  echo: 7370,
  land: 8150,
  details: 8770,
  end: 9150,
} as const;
/** The loop reuses the entrance relay. A job starts as Research picks up the
 * work, clears the previous cartridge, can pause at Review for the owner, can be
 * refused at the kernel boundary, and ends with the foundation powered. */
export const RELAY = { start: 600, clear: 850, hold: 3760, bounce: 3990, end: 4450 } as const;
export const ENTRANCE_DURATION = WORKSHOP_CUES.end;
let workshopEpoch = 0;
export function beginWorkshopEntrance(started: number) { workshopEpoch = started; }
export const clamp = (value: number) => Math.max(0, Math.min(1, value));
export const smooth = (value: number) => { const t = clamp(value); return t * t * (3 - 2 * t); };
/** Zero velocity and acceleration at both ends, including the held shots. */
export const cameraEase = (value: number) => { const t = clamp(value); return t * t * t * (t * (t * 6 - 15) + 10); };
const gesture = (time: number, start: number, end: number, ease = 55) => smooth((time - start) / ease) * (1 - smooth((time - end) / ease));

export interface WorkshopFrame {
  selected: Role;
  /** Shared performance clock keeps the overlay and page illustration in phase. */
  time: number;
  /** Omit for the living, fully revealed workshop. Milliseconds since entrance. */
  entrance?: number;
  acknowledge?: number;
  engaged?: Role | null;
  variant?: "home" | "studio" | "lab";
  selectionVisible?: boolean;
  /** Loop job: the relay runs on this clock instead of the entrance's. */
  job?: JobFrame;
  /** Kernel refusal flash; `shake` also jolts the room by one unit. */
  alarm?: AlarmFrame | null;
  /** Loop gags and speech bubbles for the home crew. */
  crew?: CrewFrame;
  /** The prompt bar on the main screen. */
  terminal?: TerminalFrame | null;
}

/** Bubble tail tip above an agent's antenna. Review is drawn mirrored, so its
 * anchor is computed here and the glyph itself is never flipped. */
export function crewEmoteAnchor(station: { role: Role; x: number; y: number }): Point {
  return [station.x + (station.role === "review" ? -25 : 17), station.y - 16];
}

const at = (story: number, a: Point, b: Point, start: number, end: number): Point => {
  const t = cameraEase((story - start) / (end - start));
  return [a[0] + (b[0] - a[0]) * t, a[1] + (b[1] - a[1]) * t];
};

/** Where the project cartridge sits on the relay clock, and how visible it is. */
export function relayParcel(story: number, job?: JobFrame, arriving = false): { at: Point; alpha: number } {
  if (job && !arriving && story < WORKSHOP_CUES.parcelAppears) {
    // The previous task's sealed cartridge sinks into the kernel as the next begins.
    const sink = smooth((story - RELAY.start) / (RELAY.clear - RELAY.start));
    return { at: [246, 178 + sink * 3], alpha: job.carried ? 1 - sink : 0 };
  }
  const alpha = arriving || job ? smooth((story - WORKSHOP_CUES.parcelAppears) / 180) : 1;
  if (story < WORKSHOP_CUES.planReceived) return { at: at(story, [115,132], [173,157], WORKSHOP_CUES.handoff, WORKSHOP_CUES.planReceived), alpha };
  if (story < WORKSHOP_CUES.parcelReceived) return { at: at(story, [173,157], [245,127], WORKSHOP_CUES.builderRelease, WORKSHOP_CUES.parcelReceived), alpha };
  if (job?.bounce && story >= RELAY.bounce) {
    // The guard at the kernel boundary hands the cartridge back; it is then discarded.
    const hit = at(RELAY.bounce, [245,127], [246,178], WORKSHOP_CUES.dispatch, WORKSHOP_CUES.docked);
    const u = cameraEase((story - RELAY.bounce) / 260);
    return {
      at: [hit[0] + (245 - hit[0]) * u, hit[1] + (127 - hit[1]) * u - Math.sin(u * Math.PI) * 9],
      alpha: alpha * (1 - smooth((story - RELAY.bounce - 260) / 200)),
    };
  }
  return { at: at(story, [245,127], [246,178], WORKSHOP_CUES.dispatch, WORKSHOP_CUES.docked), alpha };
}

/** Foundation power: lit by a docked seal, dark after a refusal, drained as a new job clears. */
export function relayPower(story: number, job?: JobFrame, arriving = false) {
  const docking = smooth((story - WORKSHOP_CUES.docked) / (WORKSHOP_CUES.powered - WORKSHOP_CUES.docked));
  if (arriving) return docking;
  if (!job) return 1;
  if (story >= WORKSHOP_CUES.docked) return job.bounce ? 0 : docking;
  return job.carried ? 1 - smooth((story - RELAY.start) / (RELAY.clear - RELAY.start)) : 0;
}

/** One authored pixel scene, used by both the cinematic camera and the page. */
export function drawWorkshop(ctx: CanvasRenderingContext2D, frame: WorkshopFrame) {
  const { selected, time, entrance, acknowledge = 1, engaged, variant = "home", selectionVisible = true, job, alarm, crew, terminal } = frame;
  const home=variant==="home", studio=variant==="studio";
  const roomStations = home ? stations : studio ? [
    {role:"implementation" as const,x:113,y:127,color:"#d9b798"},
    {role:"review" as const,x:258,y:146,color:"#cfada3"},
  ] : [
    {role:"research" as const,x:108,y:143,color:"#b4cdbb"},
    {role:"implementation" as const,x:208,y:107,color:"#a6bfc5"},
    {role:"review" as const,x:266,y:156,color:"#c4caaa"},
  ];
  const arriving = entrance !== undefined;
  const elapsed = entrance ?? ENTRANCE_DURATION;
  const room = arriving ? smooth((elapsed - 2070) / 1280) : 1;
  const foundation = arriving ? smooth((elapsed - 2690) / 760) : 1;
  const wake = (role: Role) => arriving
    ? smooth((elapsed - ({ research: 100, implementation: 1770, review: 2400 }[role])) / 500)
    : 1;
  const layer = (opacity: number) => { ctx.globalAlpha = clamp(opacity); };
  const glow = (x: number, y: number, radius: number, color: string, intensity: number) => {
    // Concentric pixel ellipses: the light belongs to the low-resolution scene.
    ctx.save();
    for (let ring = 5; ring > 0; ring--) {
      ctx.globalAlpha = intensity * (6 - ring) * .012;
      ctx.fillStyle = color;
      ctx.beginPath(); ctx.ellipse(x, y, radius * ring / 5, radius * ring / 9, 0, 0, Math.PI * 2); ctx.fill();
    }
    ctx.restore();
  };
  const { rect, poly, line, ellipse } = pixelPainter(ctx);
  ctx.save();
  ctx.setTransform(1, 0, 0, 1, 0, 0);
  ctx.clearRect(0, 0, ctx.canvas.width, ctx.canvas.height);
  ctx.scale(WORKSHOP_PIXEL_SCALE, WORKSHOP_PIXEL_SCALE);
  // A refused command jolts the room; the terminal glass (drawn last) stays put.
  const shake = alarm?.shake && alarm.age < 300 ? (Math.floor(alarm.age / 45) % 2 ? 1 : -1) : 0;
  if (shake) ctx.translate(shake, 0);
  const power = relayPower(arriving ? elapsed : job ? job.story : ENTRANCE_DURATION, job, arriving);
  layer(1);
  ctx.imageSmoothingEnabled = false;
  layer(room * .65);
  // Authored dust and stars, fixed rather than randomly changing per render.
  for (let i = 0; i < 48; i++) {
    const x = (i * 71 + 19) % 380, y = (i * 43 + 7) % 258;
    rect(x, y, i % 9 === 0 ? 2 : 1, i % 9 === 0 ? 2 : 1, i % 3 === 0 ? "#68517c" : "#302638");
  }
  layer(foundation);
  // Chio's foundation: a second layer under the application floor.
  poly([[38,168],[191,83],[346,170],[193,256]], "#1c1727", "#5c436f");
  poly([[38,168],[193,256],[193,264],[38,177]], "#30243e", "#614a76");
  poly([[193,256],[346,170],[346,178],[193,264]], "#181421", "#4b395a");
  for (let i = 0; i < 11; i++) {
    line([[48 + i * 13,174 - i * 7],[194 + i * 13,256 - i * 7]], "#30253d");
    line([[48 + i * 13,174 + i * 7],[194 + i * 13,92 + i * 7]], "#30253d");
  }
  // The maker's signature is engraved into the front of the foundation.
  ctx.save(); ctx.transform(1.2, .68, -1.2, .68, 161, 229);
  ctx.fillStyle = power > .7 ? "#d4bbdd" : "#7e668e";
  chio.forEach(({ cells }, i) => cells.forEach(([x,y,w,h]) => ctx.fillRect(x+i*GLYPH_PITCH,y,w,h)));
  ctx.restore();
  // Four little feet; the air between layers stays visible.
  for (const [x,y] of [[59,142],[191,68],[324,142],[192,217]]) {
    rect(x-2,y,4,19,"#644979"); rect(x-2,y,1,19,"#ab85c9"); rect(x-4,y+17,8,3,"#3a2b49");
  }
  layer(.025 + room * .975);
  // Workshop floor and its stepped, chamfered edges.
  poly([[50,127],[190,49],[333,129],[192,209]], home?"#352842":studio?"#3c2e39":"#29383d", home?"#b58bd1":studio?"#bc9e89":"#91b5a9");
  poly([[50,127],[192,209],[192,220],[50,139]], "#463251", "#735583");
  poly([[192,209],[333,129],[333,140],[192,220]], "#261c35", "#735583");
  for (let i = 0; i < 10; i++) {
    line([[56+i*14,130-i*7.8],[194+i*14,207-i*7.8]], "#4a355b");
    line([[56+i*14,130+i*7.8],[190+i*14,55+i*7.8]], "#4a355b");
  }
  layer(.018 + room * .982);
  // Cutaway walls: a tiny place to work, not a schematic of chip hardware.
  poly([[50,127],[50,80],[190,2],[190,49]], home?"#352a45":studio?"#46323e":"#2d4445", home?"#88659f":studio?"#a08579":"#7caaa0");
  poly([[190,2],[333,82],[333,129],[190,49]], home?"#292137":studio?"#372a37":"#23363e", home?"#79578e":studio?"#92796e":"#6f9897");
  line([[50,80],[190,2],[333,82]], home?"#b291c8":studio?"#d2b096":"#aacbb7", 2);
  for (let i = 1; i < 6; i++) {
    line([[50,80+i*8],[190,2+i*8],[333,82+i*8]], i % 2 ? "#3d2e4c" : "#443154");
  }
  // A window, a shelf of project binders, a wall clock, and a potted plant.
  poly([[72,74],[113,51],[113,78],[72,101]], "#110f21", "#ac87c6");
  poly([[76,74],[109,56],[109,75],[76,94]], "#242543");
  line([[91,64],[91,85]], "#715388", 2); line([[74,86],[111,65]], "#715388", 2);
  rect(80,77,2,2,"#c7b0e8"); rect(101,66,1,1,"#e4cbd0");
  poly([[236,39],[299,74],[299,79],[236,44]], "#8c669e");
  for (let i = 0; i < 6; i++) {
    const x = 242+i*8,y = 36+i*4.5;
    rect(x,y,5,9,["#a7baa8","#b290bd","#d1af84"][i%3]); rect(x+1,y+2,3,1,"#f4dcdf");
  }
  rect(178,17,13,14,"#a588ba"); rect(180,19,9,10,"#211a2f"); line([[184,21],[184,25],[187,25]],"#ddd0e9");
  poly([[301,123],[308,119],[315,123],[308,128]],"#a07772"); rect(304,124,8,8,"#775260");
  rect(306,111,3,13,"#839c83");rect(300,110,8,4,"#9fb68e");rect(309,106,5,8,"#bdc9a1");rect(303,102,4,8,"#839c83");
  layer(.03 + room * .97);
  if(!home) {
    // Different shelving and work surfaces give the neighboring worlds
    // their own character without labels or simulated job data.
    poly([[222,60],[278,91],[278,112],[222,81]],studio?"#2e222e":"#1a2c32",studio?"#b39988":"#83a69d");
    for(let i=0;i<3;i++) {
      line([[229+i*12,73+i*6.5],[237+i*12,77+i*6.5]],studio?"#d4b98f":"#9fbca9",2);
      line([[229+i*12,78+i*6.5],[234+i*12,80.5+i*6.5]],"#776c83");
    }
  }
  // Recessed delivery rails follow the room's isometric axes. Their dark
  // channels pass behind the benches, so the work enters each station.
  poly([[132,144],[140,140],[207,177],[199,182]], "#171423", "#6d557e");
  poly([[199,182],[264,145],[264,138],[199,175]], "#292033", "#715c83");
  for (let i = 0; i < 11; i++) {
    const shift = arriving ? Math.floor(clamp((elapsed - WORKSHOP_CUES.handoff) / 130) % 3) : Math.floor(time / 280) % 3;
    const x = 138+i*6+shift, y = 143+i*3.4+shift*.56;
    line([[x,y],[x-4,y+2]], "#78647e", 1);
    line([[204+i*5.3,175-i*3],[204+i*5.3,178-i*3]], "#66516f");
  }
  // The finished work seats in a small socket at the front-right of the room.
  poly([[232,178],[245,170],[259,178],[246,186]],"#171522", "#79618a");
  poly([[232,178],[246,186],[246,190],[232,182]],"#4c3a5b");
  poly([[246,186],[259,178],[259,182],[246,190]],"#2a2138");
  poly([[237,178],[245,173],[254,178],[246,183]],"#0f1420", "#b396b8");
  line([[238,180],[246,184],[254,180]],power>.7?"#d4dcb7":"#65556f",1);
  // The entrance and the loop share one authored relay; idle acting fills the gaps.
  const acting = arriving ? elapsed : job?.running ? job.story : undefined;
  const scripted = acting !== undefined, s = acting ?? 0;
  for (const station of roomStations) {
    const {x,y,color} = station, active = home && selectionVisible && selected === station.role;
    const awake = wake(station.role);
    glow(x + 3, y - 8, 35, color, awake * (1 - room * .65) * .35);
    layer(.018 + awake * .982);
    if (active) {
      ctx.save();
      if (arriving) layer(smooth((elapsed - WORKSHOP_CUES.land) / 500));
      poly([[x-35,y+21],[x-3,y+3],[x+38,y+26],[x+7,y+44]],"#b180d914","#8f73a9");
      ctx.restore();
    }
    const research = station.role === "research", review = station.role === "review";
    const period = research ? 7300 : review ? 9100 : 5100;
    // Positive modulo: a paused clock can trail a replayed entrance's epoch.
    const idle = ((time - workshopEpoch + x * 31) % period + period) % period;
    const attention = engaged === station.role ? 1 : active ? Math.sin(acknowledge * Math.PI) * .45 : 0;
    const leftTap = scripted
      ? research ? gesture(s, 875, 970, 40) : !review ? gesture(s, 2450, 2560, 65) : 0
      : gesture(idle, 1000, 1140, 70);
    const rightTap = scripted
      ? research ? Math.max(gesture(s, 1090, 1150, 35), gesture(s, 1200, 1270, 35)) : !review ? gesture(s, 2590, 2710, 65) : 0
      : gesture(idle, 1320, 1460, 70);
    const glance = scripted
      ? research ? gesture(s, WORKSHOP_CUES.glance, 2040, 140) : review ? -gesture(s, 3160, 3850, 150) : gesture(s, 2830, 3100, 130)
      : gesture(idle, 4200, 4600, 160);
    const blink = scripted ? research && ((s >= 650 && s < 735) || (s >= 6980 && s < 7080)) : idle>3200 && idle<3320;
    ctx.save();
    ctx.translate(x, y);
    drawStation(ctx, {rect, poly, line, ellipse}, {
      role: station.role, color, awake, engaged: attention, leftTap, rightTap,
      working: scripted
        ? research ? 1-smooth((s-1370)/230) : review ? gesture(s,3230,3690,120) : gesture(s,2310,2780,120)
        : Math.max(gesture(idle,850,1620,200),review ? .15 : 0),
      glance, headTurn: scripted && research ? gesture(s, WORKSHOP_CUES.glance+100, 2100, 160) : glance,
      blink, nod: scripted && review ? gesture(s, 3650, 3810, 80) : 0,
      thought: scripted && research ? gesture(s, 1280, 1660, 160) : 0,
      rows: scripted && research ? 1 + Number(s>970) + Number(s>1180) + Number(s>1280) : 4,
      cursor: Math.floor((arriving ? elapsed : time) / 620 + x) % 3 !== 0,
      stamp: scripted && review ? gesture(s, 3430, 3580, 70) : 0,
      surprise: crew?.surprise ?? 0, wave: crew?.wave ?? 0,
      swing: Math.sin((time + x * 23) / 130),
      posture: station.role === "implementation" ? crew?.posture ?? 0 : 0,
    });
    ctx.restore();
  }

  // Stop at every workstation. A fixed silhouette survives every contribution.
  const story = arriving ? elapsed : job ? job.story : ENTRANCE_DURATION;
  const cartridge = relayParcel(story, job, arriving);
  layer(cartridge.alpha);
  drawCartridge({rect,poly,line,ellipse},cartridge.at[0],cartridge.at[1],smooth((story-2530)/(WORKSHOP_CUES.assembled-2530)),smooth((story-WORKSHOP_CUES.sealed)/130));

  layer(foundation);
  // Docking powers the foundation in one restrained travelling illumination.
  const trace: Point[] = [[252,189],[252,220],[193,253],[43,169]];
  line(trace,"#4c3a5d",1);
  const lengths=trace.slice(1).map((point,i)=>Math.hypot(point[0]-trace[i][0],point[1]-trace[i][1]));
  let remaining=lengths.reduce((a,b)=>a+b,0)*power;
  for(let i=0;i<lengths.length && remaining>0;i++) {
    const a=trace[i], b=trace[i+1], progress=Math.min(1,remaining/lengths[i]);
    line([a,[a[0]+(b[0]-a[0])*progress,a[1]+(b[1]-a[1])*progress]],"#c4a8d7",1);
    remaining-=lengths[i];
  }
  for(let i=0;i<5;i++) rect(70+i*8,150+i*4.5,2,1,power>(i+1)/6?"#d4d9b5":"#70597f");
  if((arriving || job?.running) && power>0 && power<1) glow(246,178,22,"#d9d9b0",Math.sin(power*Math.PI)*.7);
  if (alarm) {
    // The kernel's refusal: three amber pulses along the power trace, then a short hold.
    const lit = alarm.age < 660 ? Math.floor(alarm.age / 110) % 2 === 0 : alarm.age < 1000;
    if (lit) {
      layer(foundation);
      line([[38,168],[191,83],[346,170],[193,256],[38,168]],"#b8683a");
      line(trace,"#f2a45e",1);
      for(let i=0;i<5;i++) rect(70+i*8,150+i*4.5,2,1,"#f6c07e");
    }
  }
  if (crew) {
    layer(1);
    for (const station of roomStations) {
      const emote = crew.emotes[station.role];
      if (emote) { const [ax, ay] = crewEmoteAnchor(station); drawEmote(ctx, {rect,poly,line,ellipse}, ax, ay, emote, 1.5); }
    }
  }
  if (shake) ctx.translate(-shake, 0);
  if (terminal) { layer(1); drawTerminal(ctx, {rect,poly,line,ellipse}, terminal, time); }
  layer(1);
  ctx.restore();
}
