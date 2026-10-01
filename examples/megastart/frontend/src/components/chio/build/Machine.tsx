"use client";

import { useEffect, useRef, type PointerEvent, type MouseEvent } from "react";
import { useReducedMotion } from "@/lib/motion-policy";
import { BUILD_REPLAY_EVENT } from "./build-transition";
import { cameraEase, workshopRoleAt, ROLES, WORKSHOP_PIXEL_SCALE, type Role } from "./workshop-scene";
import { createWorkshopWorld, factoryPoint, factoryView, worldPoint, WORLD_HEIGHT, WORLD_WIDTH } from "./workshop-world";
import { operatorAt } from "./workshop-operator";
import { ENTRANCE_HANDOFF, parseShiftQuery, shiftAt, skipTo } from "./workshop-shift";
import styles from "./build.module.css";

export { ROLES, type Role } from "./workshop-scene";

/** One world per mount. Loop time only moves while someone can see it, and an
 * entrance (first visit or Replay) always hands off on card one's Enter press. */
export default function Machine({ selected, engaged, wide, paused = false, illustration = true, showSelection = true, onSelect, onFocusFactory }: {
  selected: Role; engaged?: Role | null; wide: boolean; paused?: boolean; illustration?: boolean; showSelection?: boolean;
  onSelect: (role: Role) => void; onFocusFactory: () => void;
}) {
  const canvas = useRef<HTMLCanvasElement>(null);
  const pointerRole = useRef<Role | null>(null);
  const live = useRef({ selected, engaged, paused, illustration, showSelection });
  live.current = { selected, engaged, paused, illustration, showSelection };
  const camera = useRef({ value: wide ? 1 : 0, from: wide ? 1 : 0, target: wide ? 1 : 0, started: -Infinity, acknowledged: -Infinity });
  const clock = useRef({ loop: 0, scene: 0, poke: -Infinity });
  const wake = useRef(() => {});
  const reduced = useReducedMotion();
  const viewPoint = (event: PointerEvent<HTMLCanvasElement> | MouseEvent<HTMLCanvasElement>): [number, number] => {
    const bounds = event.currentTarget.getBoundingClientRect();
    return [(event.clientX - bounds.left) / bounds.width * WORLD_WIDTH, (event.clientY - bounds.top) / bounds.height * WORLD_HEIGHT];
  };
  const operatorHit = (x: number, y: number) => illustration && !reduced && camera.current.value > .9 && operatorAt(...worldPoint(x, y, camera.current.value));

  useEffect(() => {
    const cam = camera.current;
    cam.from = cam.value; cam.target = wide ? 1 : 0; cam.started = performance.now();
    wake.current();
  }, [wide]);
  useEffect(() => { camera.current.acknowledged = performance.now(); wake.current(); }, [selected]);
  useEffect(() => { wake.current(); }, [paused, engaged, illustration, showSelection]);

  useEffect(() => {
    const element = canvas.current, context = element?.getContext("2d");
    if (!element || !context) return;
    const world = createWorkshopWorld();
    if (!world) return;
    const page = element.closest<HTMLElement>("[data-build-page]");
    const qa = reduced ? null : parseShiftQuery(window.location.search);
    const time = clock.current;
    time.scene = performance.now(); time.loop = qa?.at ?? 0;
    let frame = 0, visible = true, last = 0, drawn = -Infinity;
    const draw = (now: number) => {
      const cam = camera.current;
      const progress = reduced ? 1 : cameraEase((now - cam.started) / 760);
      cam.value = cam.from + (cam.target - cam.from) * progress;
      element.dataset.camera = progress < 1 ? "moving" : "settled";
      const view = factoryView(cam.value);
      context.setTransform(1,0,0,1,0,0);
      context.clearRect(0,0,element.width,element.height);
      context.setTransform(WORKSHOP_PIXEL_SCALE,0,0,WORKSHOP_PIXEL_SCALE,0,0);
      context.transform(view.scale,-view.scale*view.skew,0,view.scale,view.x,view.y);
      const shift = reduced || !live.current.illustration ? undefined : shiftAt(time.loop);
      if (shift) {
        element.dataset.shift = `${shift.cardId}:${shift.beat}`;
        const poked = time.scene - time.poke;
        if (poked >= 0 && poked < 700) shift.operator.emote = { glyph: "!", progress: poked / 700 };
      }
      const { selected: role, engaged: control } = live.current;
      world.draw(context, {
        selected: role, time: reduced ? 4800 : qa?.frozen ? 4800 + time.loop : time.scene,
        engaged: reduced ? null : pointerRole.current ?? control ?? null,
        acknowledge: reduced ? 1 : Math.min(1, (now - cam.acknowledged) / 440), selectionVisible: cam.value < .1 && live.current.showSelection,
      }, { expansion: cam.value, shift });
    };
    const paint = (now: number) => {
      frame = 0;
      if (!visible || document.hidden) { last = 0; return; }
      // Clamp the step so a stalled frame never jumps the shift.
      const step = last ? Math.min(100, now - last) : 0; last = now;
      const entering = page?.hasAttribute("data-build-entering") ?? false;
      const still = reduced || live.current.paused || !!qa?.frozen;
      if (!still) time.scene += step;
      // A QA moment is a deep link: it survives a replayed entrance.
      if (entering && !qa) time.loop = ENTRANCE_HANDOFF;
      // An entrance that ended early (skip, Esc) hands over the moment it was showing.
      const handoff = page?.dataset.buildHandoff;
      if (!entering && handoff !== undefined) {
        if (!qa) time.loop = Number(handoff) || 0;
        delete page!.dataset.buildHandoff;
      }
      else if (!still && !entering) time.loop += step;
      const moving = now - camera.current.started < 800;
      // Room poses update at 24fps; the short camera interaction uses every frame.
      if (moving || now - drawn >= 1000 / 24) { draw(now); drawn = now; }
      if (still && !moving && !entering) { last = 0; return; }
      frame = requestAnimationFrame(paint);
    };
    const resume = () => { if (!frame && visible && !document.hidden) frame = requestAnimationFrame(paint); };
    wake.current = () => { drawn = -Infinity; resume(); };
    const observer = new IntersectionObserver(([entry]) => { visible = entry.isIntersecting; resume(); });
    observer.observe(element);
    document.addEventListener("visibilitychange", resume);
    const replay = () => wake.current();
    window.addEventListener(BUILD_REPLAY_EVENT, replay);
    resume();
    return () => {
      cancelAnimationFrame(frame); observer.disconnect();
      document.removeEventListener("visibilitychange", resume);
      window.removeEventListener(BUILD_REPLAY_EVENT, replay);
      wake.current = () => {};
    };
  }, [reduced]);

  return <canvas ref={canvas} width={WORLD_WIDTH*WORKSHOP_PIXEL_SCALE} height={WORLD_HEIGHT*WORKSHOP_PIXEL_SCALE} data-build-machine data-view={wide?"world":"factory"} className={styles.machine} role="img"
    onPointerMove={event=>{
      if(event.pointerType==="touch") return;
      const [vx,vy]=viewPoint(event), [x,y]=factoryPoint(vx,vy,camera.current.value), role=workshopRoleAt(x,y);
      if(role!==pointerRole.current) { pointerRole.current=role; wake.current(); }
      event.currentTarget.style.cursor=role || (wide && x>32 && x<350 && y>0 && y<270) || operatorHit(vx,vy)?"pointer":"default";
    }}
    onPointerLeave={()=>{ if(pointerRole.current) { pointerRole.current=null; wake.current(); } }}
    onClick={event=>{
      const [vx,vy]=viewPoint(event), [x,y]=factoryPoint(vx,vy,camera.current.value), role=workshopRoleAt(x,y);
      if(role) onSelect(role);
      else if(operatorHit(vx,vy)) {
        // An easter egg: poke the operator and it gets on with the next prompt.
        const time=clock.current; time.loop=skipTo(time.loop); time.poke=time.scene; wake.current();
      }
      else if(wide && x>32 && x<350 && y>0 && y<270) onFocusFactory();
    }}
    aria-label={wide
      ? "A workshop of agents lives inside a larger agent’s terminal. Neighboring terminals contain other workshops. At the console, an operator types prompts such as “make no mistakes”, and the Chio kernel answers each with a receipt, a refusal, or a question for the owner. Architectural illustration. Use Inside and the role controls above to explore the software factory."
      : `Your software factory: research, implementation, and review agents on the Chio kernel. ${showSelection ? `${ROLES.find(item=>item.id===selected)?.name} is selected.` : "Project is selected."} Architectural illustration.`}>
    A workshop inside another agent’s terminal. Use the view and role buttons above to explore.
  </canvas>;
}
