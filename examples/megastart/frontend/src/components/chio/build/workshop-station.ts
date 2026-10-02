import type { PixelPainter, Point } from "./workshop-pixels";
import type { Role } from "./workshop-scene";

export const TERMINAL_SCREEN = { x: -27, y: -38, width: 34, height: 34 * 280 / 384, shear: .125 } as const;

export interface StationPose {
  role: Role;
  color: string;
  awake: number;
  engaged: number;
  leftTap: number;
  rightTap: number;
  glance: number;
  headTurn: number;
  blink: boolean;
  nod: number;
  thought: number;
  rows: number;
  cursor: boolean;
  stamp: number;
  working: number;
  /** Loop gags, all neutral at 0. */
  surprise?: number;
  wave?: number;
  /** Wave oscillation in [-1, 1], supplied by the scene clock. */
  swing?: number;
  posture?: number;
}

/** Authored in local workshop units. The same drawing survives the hero close
 * shot and the wide view; there is no sprite swap during the camera move. */
export function drawStation(ctx: CanvasRenderingContext2D, p: PixelPainter, pose: StationPose, screen?: { image?: CanvasImageSource; opacity?: number }) {
  const { rect, poly, line, ellipse } = p;
  const { role, color, awake, engaged, leftTap, rightTap, glance, headTurn, blink, nod, thought, rows, cursor, stamp, working, surprise = 0, wave = 0, swing = 0, posture = 0 } = pose;
  const research = role === "research", review = role === "review";
  const opacity = ctx.globalAlpha;
  const shellLight = research ? "#dde2d6" : review ? "#eee0c3" : "#e9daf3";
  const shellShade = research ? "#7d9290" : review ? "#a8957b" : "#9587af";
  const armShade = research ? "#718b87" : review ? "#9b876f" : "#8f7ba5";

  // Contact shadow, two trestles, feet and the recessed steel crossbrace.
  poly([[-32,20],[-7,5],[37,27],[12,41]], "#100d1a70");
  poly([[24,3],[27,4],[27,28],[24,27]],"#453e53");
  line([[25,7],[25,26]],"#766a83");
  poly([[-29,-2],[-26,-.5],[-26,24],[-29,22.5]], "#666174");
  poly([[-26,-.5],[-24,-1.5],[-24,23],[-26,24]], "#3c394b");
  poly([[5,15],[8,16.5],[8,41],[5,39.5]], "#5f596e");
  poly([[8,16.5],[10,15.5],[10,40],[8,41]], "#383044");
  poly([[-28,16],[8,34],[8,37],[-28,19]], "#2e283e");
  line([[-28,16],[8,34]], "#8c7c9a");
  poly([[-32,24],[-27,21.5],[-21,24.5],[-26,27]], "#383444", "#797083");
  poly([[2,41],[7,38.5],[13,41.5],[8,44]], "#34303f", "#6d627b");
  rect(-28,5,1,12,"#a39aac"); rect(6,23,1,11,"#918198");
  // A small under-desk drawer and a cable that follows the frame.
  poly([[-19,3],[-5,10],[-5,18],[-19,11]],"#4b4058");
  line([[-17,7],[-8,11.5]],"#9f8ba8");
  line([[5,-3],[10,0],[10,20],[17,24]],"#211c2c",1.5);
  line([[6,-3],[11,0],[11,19]],"#62566e");

  // The desktop has a dark core, a broad warm surface and a thin machined lip.
  poly([[-34,-5],[6,15],[6,19],[-34,-1]],"#67506c");
  poly([[6,15],[30,3],[30,7],[6,19]],"#3c304b");
  poly([[-34,-5],[-10,-17],[30,3],[6,15]],"#a08b9d");
  poly([[-32,-5],[-10,-16],[28,3],[6,14]],"#927f92");
  poly([[-30,-5],[-10,-15],[15,-2],[-6,8]],"#a792a2");
  line([[-34,-5],[-10,-17],[30,3]],"#dcc3c7");
  line([[-34,-4],[6,16],[30,4]],"#b8a0b4");
  line([[-33,-.5],[6,19],[29,7.5]],"#352a40");
  // Grain stays sparse and follows the plane rather than adding random noise.
  line([[-29,-3],[-19,2]],"#b29baa"); line([[12,9],[19,5.5]],"#b39bad");
  rect(-29,-1.5,1,1,"#cfb7c0"); rect(6,16.5,1,1,"#ddc8cf");

  // Pool of reflected screen light, clipped by the authored desk footprint.
  ctx.globalAlpha = opacity * awake * (.22 + engaged * .12);
  poly([[-17,-10],[3,-9],[21,4],[5,12],[-22,-1]],color);
  ctx.globalAlpha = opacity;

  // Monitor foot, shadow, neck, rear shell and bevelled three-quarter bezel.
  poly([[-14,-9],[-5,-13],[9,-6],[1,-2]],"#54445d70");
  poly([[-11,-10],[-5,-13],[5,-8],[-1,-5]],"#4b465d", "#af99b8");
  poly([[-7,-10],[-4,-11.5],[-4,-20],[-7,-21]],"#8b7c9c");
  poly([[-4,-11.5],[-2,-12.5],[-2,-21],[-4,-20]],"#50465e");
  if(screen) {
    const {x,y,width,height,shear}=TERMINAL_SCREEN;
    // A larger terminal repeats the original bezel, vent and ivory power light.
    // Its inset contains the exact living workshop the camera started inside.
    poly([[x-2,y-2],[x+1,y-5],[x+width+5,y-2+(width+4)*shear],[x+width+2,y+(width+4)*shear]],"#b7a5ba");
    poly([[x+width+2,y+(width+4)*shear],[x+width+5,y-2+(width+4)*shear],[x+width+5,y+height+width*shear],[x+width+2,y+height+2+width*shear]],"#4e405e");
    poly([[x-2,y-2],[x+width+2,y+width*shear-2],[x+width+2,y+height+width*shear+2],[x-2,y+height+2]],"#a08ba8");
    line([[x-2,y-2],[x+width+2,y+width*shear-2]],"#e2cddc");
    line([[x-2,y-1],[x-2,y+height+2],[x+width+1,y+height+width*shear+2]],"#74627e");
    poly([[x-.5,y-.5],[x+width+.5,y+width*shear-.5],[x+width+.5,y+height+width*shear+.5],[x-.5,y+height+.5]],"#201c2e");
    ctx.save();
    ctx.globalAlpha=screen.opacity ?? opacity;
    ctx.transform(1,shear,0,1,x,y);
    ctx.fillStyle="#09080d"; ctx.fillRect(0,0,width,height);
    ctx.imageSmoothingEnabled=false;
    if(screen.image) ctx.drawImage(screen.image,0,0,width,height);
    ctx.restore();
    rect(x+width-1,y+height+width*shear+1,1.5,.5,"#e9dbb9");
    for(let i=0;i<5;i++) line([[x+width+3,y+8+i*2],[x+width+4,y+7+i*2]],"#2c2538");
  } else {
  poly([[-20,-33],[-17,-36],[7,-33],[4,-30]],"#b7a5ba");
  poly([[4,-30],[7,-33],[7,-13],[4,-10]],"#4e405e");
  poly([[-20,-33],[4,-30],[4,-10],[-20,-13]],"#a08ba8");
  line([[-20,-33],[4,-30]],"#e2cddc");
  line([[-20,-32],[-20,-13],[3,-10]],"#74627e");
  poly([[-18,-31],[2,-28.5],[2,-13],[-18,-15.5]],"#292435");
  poly([[-17,-30],[1,-27.5],[1,-14],[-17,-16]],"#151c29");
  poly([[-17,-30],[1,-27.5],[1,-25],[-17,-27]],"#22303a");
  line([[-16.5,-29.5],[.5,-27.5]],"#57606a");
  for (let i=0;i<4;i++) line([[5,-26+i*2],[6,-27+i*2]],"#2c2538");
  rect(-18,-14.5,2,.5,"#d2bdce");
  rect(0,-12,1,.5,awake>.6?color:"#605065");
  // Screen content shares the screen's shallow perspective.
  const screenLine = (x: number, y: number, length: number, ink: string) => line([[x,y],[x+length,y+length*.125]],ink);
  ctx.globalAlpha = opacity * awake;
  if (research) {
    screenLine(-15,-26,7,color);
    if (rows>1) { line([[-14,-23],[-14,-20],[-11,-19.5]],"#6f9a94"); screenLine(-10,-19.5,8,color); }
    if (rows>2) { line([[-14,-22],[-10,-21.5]],"#6f9a94"); screenLine(-9,-21.5,6,"#e1d5b4"); }
    if (rows>3) { screenLine(-11,-17.5,6,"#6d9e95"); rect(-3,-17,1,1,"#dbe9ce"); }
  } else if (review) {
    screenLine(-15,-26,11,"#897c75");
    line([[-12,-21],[-9,-18],[-4,-23]],color,1);
    screenLine(-14,-16.5,8,"#736e7e");
  } else {
    for(let row=0;row<4;row++) {
      screenLine(-15,-26+row*2.5,2,"#695c83");
      screenLine(-11+(row%2)*2,-25.5+row*2.5,7-row%3,color);
    }
  }
  if(cursor) rect(-3,-15.5,1.5,.5,color);
  ctx.globalAlpha = opacity;

  }

  // Keyboard: recessed deck, individual staggered key clusters, spacebar.
  const keyPoint = (u: number, v: number): Point => [-7+u-v, -1+u*.5+v*.5];
  const key = (u: number,v: number,w: number,d: number,ink: string) => poly([keyPoint(u,v),keyPoint(u+w,v),keyPoint(u+w,v+d),keyPoint(u,v+d)],ink);
  key(-1,-1,17,7,"#493e54"); key(-1,-1.5,17,6.5,"#c7b6c7"); key(0,-.5,15,5,"#75667e");
  for(let row=0;row<3;row++) for(let col=0;col<7;col++) {
    key(col*2+row*.25,row*1.3,1.5,.9,(col+row)%4===0?"#a7b5b2":"#e1d3d7");
  }
  key(3,4,7,1,"#cbbccf"); key(12,4,2,1,"#b59ac2");
  // Narrow cable curls behind the keyboard, visibly connecting the objects.
  line([[-7,-2],[-10,-4],[-8,-5],[-5,-4]],"#66536f");

  if (research) {
    // A folded schematic, drawn on its own plane, and a ceramic espresso cup.
    poly([[-28,-1],[-22,-4],[-14,0],[-20,3]],"#59495d50");
    poly([[-28,-2],[-22,-5],[-14,-1],[-20,2]],"#d4c9b5");
    poly([[-22,-5],[-22,-2],[-18,-3]],"#f0dfc4");
    line([[-25,-2],[-22,-.5],[-20,-1.5],[-18,-.5]],"#788b87");
    ellipse(-24,-8,3,1.5,"#655162");
    rect(-27,-12,5,4,"#a5bdb1"); rect(-26.5,-12,1,4,"#d5dfcd");
    ellipse(-24.5,-12,2.5,1,"#dce3d3"); ellipse(-24.5,-12,1.5,.5,"#534c51");
    line([[-22,-11],[-20.5,-11],[-20.5,-9],[-22,-9]],"#bfcec1");
  } else if (review) {
    // A low task lamp clamps to the outer edge, entirely clear of the screen.
    poly([[-34,-5],[-30,-7],[-27,-5.5],[-31,-3.5]],"#b5a082", "#dfc99d");
    line([[-33,-4],[-33,0],[-30,1.5]],"#8e785f",1.5);
    line([[-31,-5],[-31,-16],[-27,-21]],"#c7b18c",1.5);
    rect(-32,-17,2,2,"#e6d3aa");
    poly([[-29,-23],[-25,-25],[-21,-20],[-27,-17]],"#aa8c6b", "#e7d0a3");
    line([[-27,-17],[-21,-20]],"#fff0c6",1);
    ctx.globalAlpha=opacity*.1*awake;
    poly([[-27,-17],[-21,-20],[-10,7],[-26,6]],"#f7d9a1");
    ctx.globalAlpha=opacity;
    poly([[-29,4],[-19,-1],[-9,4],[-19,9]],"#6e6263", "#b5a384");
    line([[-26,4],[-19,7.5],[-12,4]],"#c7b694");
  } else {
    // A tool roll and two spare components distinguish the builder's bench.
    poly([[-29,-2],[-22,-5.5],[-13,-1],[-20,2.5]],"#55475f", "#aa8eb4");
    for(let i=0;i<3;i++) line([[-26+i*3,-2+i*1.5],[-22+i*3,-4+i*1.5]],i===1?"#d5b48c":"#c1abc8",1);
    poly([[-26,-11],[-22,-13],[-18,-11],[-22,-9]],"#af97c8");
    line([[-25,-10],[-22,-8.5],[-18,-10.5]],"#59486a");
  }

  // Review works from the opposite edge, leaving the inspection pad visible.
  // Upper arms fall beside the torso; the near elbow bends back toward a key.
  ctx.save();
  if(review) { ctx.translate(-8,0); ctx.scale(-1,1); }
  const lean = (leftTap+rightTap)*.35;
  const bx=18, by=30;
  const look=glance+engaged*.7+surprise*1.4;
  const hx=bx+Math.round((headTurn+engaged*.7)*2)*.5-lean, hy=by-26+Math.round(nod*2)*.5-Math.round(Math.min(1,surprise+posture)*2)*.5;
  ellipse(bx+1,by+1,10,3,"#17132090");
  // Feet with toe caps, heel shadows, ankle joints.
  rect(bx-6,by-6,3,5,"#6e617d"); rect(bx+3,by-5,3,5,"#55475e");
  poly([[bx-8,by-2],[bx-3,by-2],[bx-1,by],[bx-1,by+2],[bx-8,by+1]],"#b7a6c0");
  poly([[bx+2,by-1],[bx+7,by-1],[bx+9,by+1],[bx+8,by+3],[bx+2,by+2]],"#9b89ac");
  line([[bx-8,by-2],[bx-3,by-2]],"#e5d3df"); line([[bx+2,by-1],[bx+7,by-1]],"#cebbd2");
  // The far hand rests near the hip; a short wrist movement adds asymmetry.
  line([[bx+5,by-17],[bx+7,by-11],[bx+5,by-8-rightTap]],armShade,3);
  ellipse(bx+5,by-8-rightTap,1.75,1.5,shellLight);
  // Torso and contrasting side panel.
  poly([[bx-6,by-19],[bx+3,by-18],[bx+7,by-15],[bx+7,by-6],[bx+3,by-4],[bx-6,by-6]],"#8e7b9f");
  poly([[bx+3,by-18],[bx+7,by-15],[bx+7,by-6],[bx+3,by-4]],"#62536f");
  rect(bx-5,by-18,7,1,color); rect(bx-4,by-14,4,3,"#473e58");
  rect(bx-3.5,by-13.5,3,1,awake>.8?color:"#7d718a");
  rect(bx-4,by-8,2,1,"#c5b6ca"); rect(bx-.5,by-8,1,1,"#4c415a");
  if (posture > .5) {
    // A promotion, visibly. The work that follows is identical.
    poly([[bx-3,by-18],[bx,by-18],[bx-1,by-16.5],[bx-2,by-16.5]],"#e08a7c");
    poly([[bx-2.5,by-16.5],[bx-.5,by-16.5],[bx,by-11],[bx-1.5,by-9.5],[bx-3,by-11]],"#c9665c");
  }
  // Neck, top facets, coloured shell and shadowed right side.
  rect(hx-2,hy+3,4,4,"#504b60");
  poly([[hx-9,hy-10],[hx-6,hy-13],[hx+6,hy-12],[hx+9,hy-9],[hx+6,hy-7],[hx-7,hy-8]],shellLight);
  poly([[hx-9,hy-10],[hx+5,hy-9],[hx+5,hy+3],[hx-7,hy+2],[hx-9,hy]],color);
  poly([[hx+5,hy-9],[hx+9,hy-11],[hx+9,hy],[hx+5,hy+3]],shellShade);
  line([[hx-8,hy-10],[hx+5,hy-9]],"#eef0dc");
  // Recessed dark visor, a lit lower lip, and expressive half-pixel pupils.
  poly([[hx-7.5,hy-7.5],[hx+3.5,hy-6.5],[hx+3.5,hy-.5],[hx-7.5,hy-1.5]],"#202437");
  line([[hx-7,hy-1],[hx+3,hy]],"#d4e4cc");
  const eyes = Math.round(look*2)*.5-1;
  rect(hx-5.5+eyes,hy-5+(blink?1:0),2,blink?.5:2,"#f4e9d4");
  rect(hx+.5+eyes,hy-4.5+(blink?1:0),2,blink?.5:2,"#f4e9d4");
  rect(hx+6,hy-6,1,3,"#536b70"); rect(hx+6,hy-6,1,1,"#c7d3c5");
  // Screen-side reflected light and antenna with a little copper collar.
  ctx.globalAlpha=opacity*awake*.3;
  rect(hx-9,hy-8,1.5,7,"#e8efcb");
  ctx.globalAlpha=opacity;
  rect(hx-1,hy-17,1,5,"#797184"); rect(hx-2,hy-14,3,1,"#bba18f");
  rect(hx-2,hy-18,3,2,thought>.2 || engaged>.2 || surprise>.2 || posture>.5?"#eef1cf":"#c0a8d2");
  rect(hx-1.5,hy-18,.5,.5,"#fff0dd");
  // A tucked elbow and a short forearm read as working, even in a still frame.
  const reach=review?Math.max(working,stamp):working;
  let wx=bx-7+(7-(bx-7))*reach, wy=by-10+(10-(by-10))*reach+(review?stamp:leftTap)*.75;
  let ex=bx-6, ey=by-11;
  if (wave > 0) {
    // A raised hand overrides the working arm.
    wx+=(bx-8+swing*2.5-wx)*wave; wy+=(by-34-wy)*wave; ex+=(bx-10-ex)*wave; ey+=(by-23-ey)*wave;
  }
  line([[bx-5,by-17],[ex,ey],[wx,wy]],armShade,3);
  line([[bx-5.5,by-17],[ex-.5,ey],[wx-.5,wy]],color,1.5);
  ellipse(ex,ey,1.5,1.5,color);
  poly([[wx-2,wy-1],[wx+1,wy-.5],[wx+2,wy+1],[wx,wy+2],[wx-2.5,wy+.5]],shellLight);
  line([[wx-1,wy+.5],[wx+1,wy+1.5]],shellShade);
  ctx.restore();
}
