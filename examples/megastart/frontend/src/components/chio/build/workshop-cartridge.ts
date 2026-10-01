import type { PixelPainter } from "./workshop-pixels";

/** The ivory label and clipped corner never change, so the viewer can follow
 * the same project through research, assembly, inspection and delivery. */
export function drawCartridge(p: PixelPainter, x: number, y: number, built: number, sealed: number) {
  const {poly,line,rect,ellipse}=p;
  ellipse(x,y+5,10,3,"#100e1a65");
  poly([[x-9,y-1],[x-1,y-5],[x+7,y-1],[x+9,y+1],[x,y+5],[x-9,y+.5]],"#51445f", "#ac96b9");
  poly([[x-9,y+.5],[x,y+5],[x,y+8],[x-9,y+3.5]],"#655271");
  poly([[x,y+5],[x+9,y+1],[x+9,y+4],[x,y+8]],"#342b43");
  poly([[x-7,y-1],[x-1,y-4],[x+5,y-1],[x-1,y+2]],"#efdfbb", "#ffedcc");
  line([[x-4,y-1],[x-2,y],[x+1,y-1.5]],"#7d9384");
  for(let i=0;i<3;i++) line([[x-7+i*2,y+3],[x-7+i*2,y+4]],"#cfb27f");
  if(built>0) {
    const drop=(1-built)*4;
    poly([[x+1,y+1-drop],[x+5,y-1-drop],[x+7,y-drop],[x+3,y+2-drop]],"#a5b6aa", "#e0d9c4");
    rect(x+3,y+.5-drop,1,.5,"#374749");
  }
  if(sealed>.4) {
    line([[x-3,y+3],[x-1,y+4.5],[x+2,y+2.5]],"#ede4bf",1);
    rect(x+5,y+3.5,1,1,"#cbd9b2");
  }
}
