// Static layout coordinates for the four-quadrant topology graph.
//
// The coordinates are chosen for a 1000x700
// viewBox. Node ids match the topology.json entries produced by orchestrate.py.

export type QuadrantKey = "tl" | "tr" | "bl" | "br";

export interface QuadrantRect {
  x: number;
  y: number;
  w: number;
  h: number;
}

export const QUAD: Record<QuadrantKey, QuadrantRect> = {
  tl: { x: 40, y: 40, w: 460, h: 300 },
  tr: { x: 500, y: 40, w: 460, h: 300 },
  br: { x: 500, y: 360, w: 460, h: 300 },
  bl: { x: 40, y: 360, w: 460, h: 300 },
};

export interface NodePos {
  x: number;
  y: number;
}

export const NODE_POS: Record<string, NodePos> = {
  // Atlas (tl)
  "atlas.treasury": { x: 110, y: 140 },
  "atlas.procurement": { x: 260, y: 180 },
  "atlas.approver": { x: 130, y: 260 },
  "atlas.mkt-broker": { x: 400, y: 180 },
  "atlas.mcp.review": { x: 490, y: 100 },
  // ProofWorks (tr)
  "proofworks.provider": { x: 620, y: 180 },
  "proofworks.delegator": { x: 760, y: 240 },
  "proofworks.subcontract-desk": { x: 900, y: 260 },
  "proofworks.mcp.review": { x: 510, y: 300 },
  // CipherWorks (br)
  "cipherworks.subcontractor": { x: 780, y: 510 },
  "cipherworks.attestor": { x: 900, y: 440 },
  // Meridian (bl)
  "meridian.settlement": { x: 210, y: 480 },
  "meridian.settlement-desk": { x: 370, y: 470 },
  "meridian.auditor": { x: 110, y: 580 },
  "meridian.mcp.web3": { x: 490, y: 600 },
};

export function hexPoints(r: number): string {
  const pts: string[] = [];
  for (let i = 0; i < 6; i += 1) {
    const a = (Math.PI / 3) * i + Math.PI / 6;
    pts.push(`${(r * Math.cos(a)).toFixed(2)},${(r * Math.sin(a)).toFixed(2)}`);
  }
  return pts.join(" ");
}

export function edgePath(a: NodePos, b: NodePos, kind: string): string {
  const dx = b.x - a.x;
  const dy = b.y - a.y;
  if (kind === "intra") {
    return `M${a.x} ${a.y} L${b.x} ${b.y}`;
  }
  const mx = (a.x + b.x) / 2;
  const my = (a.y + b.y) / 2;
  const len = Math.sqrt(dx * dx + dy * dy) || 1;
  const nx = -dy / len;
  const ny = dx / len;
  const curv = Math.min(60, len * 0.15);
  const cx = mx + nx * curv;
  const cy = my + ny * curv;
  return `M${a.x} ${a.y} Q${cx} ${cy} ${b.x} ${b.y}`;
}
