import { ATELIER_SCREEN, ATELIER_NEIGHBORS, drawAtelierShell, drawBloom, drawComet, drawCup, drawKeyPress, drawStatusLight, drawSteam, CUP_ON_DESK } from "./workshop-atelier";
import { drawOperator, drawOperatorMarks, NEUTRAL_POSE, operatorPose } from "./workshop-operator";
import { pixelPainter, type Point } from "./workshop-pixels";
import { cameraEase as cueEase, clamp, RELAY, smooth, drawWorkshop, WORKSHOP_CUES as cues, WORKSHOP_HEIGHT, WORKSHOP_PIXEL_SCALE, WORKSHOP_WIDTH, type WorkshopFrame } from "./workshop-scene";
import type { ShiftFrame } from "./workshop-shift";

export const WORLD_WIDTH = 720;
export const WORLD_HEIGHT = 525;
export const HOME_FACTORY = {
  x: ATELIER_SCREEN.x,
  y: ATELIER_SCREEN.y,
  scale: ATELIER_SCREEN.width / WORKSHOP_WIDTH,
  shear: ATELIER_SCREEN.shear,
};

const socketOf = (s: { x: number; y: number; width: number; shear: number }): Point => {
  const scale = s.width / WORKSHOP_WIDTH;
  return [s.x + 246 * scale, s.y + (178 + s.shear * 246) * scale];
};
/** Where each workshop's kernel socket appears in the wide shot. */
export const HOME_SOCKET = socketOf(ATELIER_SCREEN);
export const PEER_SOCKET = socketOf(ATELIER_NEIGHBORS[1]);
const OUTBOUND = ['#f6ecfd', '#dcc3ee', '#c3a4dc', '#a384bd', '#86699f', '#4f3e61'] as const;
const INBOUND = ['#eef9f1', '#c9e6d3', '#a9cdb5', '#88ad96', '#6c8d78', '#3f5448'] as const;

/** Unskewing the nested screen keeps the first two shots in the workshop's
 * original coordinate system. The second pullback gently restores its tilt. */
export function factoryView(expansion: number) {
  const closeScale = WORLD_WIDTH / (WORKSHOP_WIDTH * HOME_FACTORY.scale);
  const scale = closeScale + (1-closeScale)*expansion;
  const skew = HOME_FACTORY.shear*(1-expansion);
  return {
    scale, skew,
    x: -HOME_FACTORY.x*closeScale*(1-expansion),
    y: -(HOME_FACTORY.y-HOME_FACTORY.shear*HOME_FACTORY.x)*closeScale*(1-expansion),
  };
}

/** Canvas view coordinates back to world units for the current camera. */
export function worldPoint(x: number, y: number, expansion: number): Point {
  const camera = factoryView(expansion);
  const wx = (x - camera.x) / camera.scale;
  return [wx, (y - camera.y) / camera.scale + camera.skew * wx];
}

export function factoryPoint(x: number, y: number, expansion: number): [number,number] {
  const [wx, wy] = worldPoint(x, y, expansion);
  return [(wx-HOME_FACTORY.x)/HOME_FACTORY.scale,
    (wy-HOME_FACTORY.y-HOME_FACTORY.shear*(wx-HOME_FACTORY.x))/HOME_FACTORY.scale];
}

/** Factory layers update at 24fps; the outer architecture is cached once.
 * The final view has its own authored console and seated operator. */
export function createWorkshopWorld() {
  const surfaces=Array.from({length:3},()=>{
    const canvas=document.createElement("canvas");
    canvas.width=WORKSHOP_WIDTH*WORKSHOP_PIXEL_SCALE;
    canvas.height=WORKSHOP_HEIGHT*WORKSHOP_PIXEL_SCALE;
    return {canvas,context:canvas.getContext("2d")};
  });
  const shell=document.createElement("canvas");
  shell.width=WORLD_WIDTH*WORKSHOP_PIXEL_SCALE;shell.height=WORLD_HEIGHT*WORKSHOP_PIXEL_SCALE;
  const shellContext=shell.getContext("2d");
  if(!shellContext || surfaces.some(surface=>!surface.context)) return null;
  shellContext.scale(WORKSHOP_PIXEL_SCALE,WORKSHOP_PIXEL_SCALE);
  drawAtelierShell(shellContext);
  drawWorkshop(surfaces[1].context!,{selected:"implementation",time:2700,variant:"studio",selectionVisible:false});
  const drawLab = (frame: Partial<WorkshopFrame> = {}) => drawWorkshop(surfaces[2].context!,{selected:"research",time:4100,variant:"lab",selectionVisible:false,...frame});
  drawLab();
  let lab = { live: false, drawn: -Infinity };
  let last=-Infinity, lastShift=NaN, previousSelection="", previousEngaged:WorkshopFrame["engaged"], previousVisibility:boolean|undefined;
  return {
    draw(ctx:CanvasRenderingContext2D,frame:WorkshopFrame,options:{expansion:number; shift?:ShiftFrame}) {
      const {expansion, shift}=options;
      const shiftMoved=shift ? !(Math.abs(shift.t-lastShift)<1000/24) : !Number.isNaN(lastShift);
      if(frame.time<last || frame.time-last>=1000/24 || shiftMoved || frame.selected!==previousSelection || frame.engaged!==previousEngaged || frame.selectionVisible!==previousVisibility) {
        // The entrance runs its own relay; only the loop hands the workshop a job.
        drawWorkshop(surfaces[0].context!,shift ? {...frame,job:frame.entrance===undefined?shift.job:undefined,terminal:shift.terminal,crew:shift.crew,alarm:shift.alarm} : frame);
        last=frame.time;lastShift=shift?.t ?? NaN;previousSelection=frame.selected;previousEngaged=frame.engaged;previousVisibility=frame.selectionVisible;
      }
      // Peering wakes the right-hand workshop: it brightens and runs the relay quickly.
      const peer=shift?.peer ?? null;
      const wake=peer ? smooth((peer.age-700)/200)*(1-smooth((peer.age-1800)/250)) : 0;
      if(peer && wake>0 && frame.time-lab.drawn>=1000/12) {
        drawLab({time:frame.time,job:{story:RELAY.start+clamp((peer.age-700)/1100)*(RELAY.end-RELAY.start),running:true,bounce:false,carried:false}});
        lab={live:true,drawn:frame.time};
      } else if(wake===0 && lab.live) { drawLab(); lab={live:false,drawn:-Infinity}; }
      const elapsed=frame.entrance;
      const reveal=elapsed===undefined?smooth(expansion*2):smooth((elapsed-cues.recurse)/850);
      const alpha=ctx.globalAlpha;
      ctx.save();ctx.imageSmoothingEnabled=false;
      if(reveal>0) {
        ctx.globalAlpha=alpha*reveal;
        ctx.drawImage(shell,0,0,WORLD_WIDTH,WORLD_HEIGHT);
        ATELIER_NEIGHBORS.forEach((screen,index)=>{
          ctx.save();ctx.globalAlpha=alpha*reveal*(index===0?.45:.56+.44*wake);
          const scale=screen.width/WORKSHOP_WIDTH;
          ctx.transform(scale,scale*screen.shear,0,scale,screen.x,screen.y);
          ctx.drawImage(surfaces[index+1].canvas,0,0,WORKSHOP_WIDTH,WORKSHOP_HEIGHT);
          ctx.restore();
        });
      }
      ctx.save();ctx.globalAlpha=alpha;
      ctx.transform(HOME_FACTORY.scale,HOME_FACTORY.scale*HOME_FACTORY.shear,0,HOME_FACTORY.scale,HOME_FACTORY.x,HOME_FACTORY.y);
      ctx.drawImage(surfaces[0].canvas,0,0,WORKSHOP_WIDTH,WORKSHOP_HEIGHT);
      // A third, intentionally tiny echo appears only once the outer world exists.
      if(expansion>.8) {
        ctx.save();ctx.globalAlpha=alpha*smooth((expansion-.8)/.2)*.8;
        const scale=17/WORKSHOP_WIDTH;
        ctx.transform(scale,scale*.125,0,scale,94,89);
        ctx.drawImage(surfaces[2].canvas,0,0,WORKSHOP_WIDTH,WORKSHOP_HEIGHT);
        ctx.restore();
      }
      ctx.restore();
      if(reveal>0) {
        ctx.globalAlpha=alpha*reveal;
        const p=pixelPainter(ctx);
        const holding=!!shift?.operator.holding;
        if(!holding) drawCup(p,CUP_ON_DESK,0,true);
        if(shift) {
          if(!holding) drawSteam(ctx,p,frame.time);
          drawStatusLight(p,shift.status,shift.statusAge);
          if(shift.operator.key) drawKeyPress(p,shift.operator.key.to,shift.operator.key.press);
        }
        const response=elapsed===undefined?.2:smooth((elapsed-cues.echo)/180)*(1-smooth((elapsed-cues.echo-500)/300));
        const pose=shift ? operatorPose(shift.operator) : NEUTRAL_POSE;
        drawOperator(ctx,pose,response,holding);
        if(shift) drawOperatorMarks(ctx,pose,shift.operator.emote,shift.operator.sleep,frame.time);
        if(peer) {
          drawBloom(ctx,p,PEER_SOCKET,wake);
          if(peer.age<800) drawComet(ctx,p,HOME_SOCKET,PEER_SOCKET,cueEase(peer.age/800),OUTBOUND);
          if(peer.age>=1800) drawComet(ctx,p,PEER_SOCKET,HOME_SOCKET,cueEase((peer.age-1800)/800),INBOUND);
        }
      }
      ctx.restore();
    },
  };
}
