export type Point = [number, number];

/** Half-unit pixels let the close-up carry bevels, keys and joints. Geometry is
 * rasterized explicitly: scaling an antialiased polygon magnifies soft edges. */
export const WORKSHOP_PIXEL_SCALE = 2;
const pixel = 1 / WORKSHOP_PIXEL_SCALE;
const snap = (n: number) => Math.round(n * WORKSHOP_PIXEL_SCALE) / WORKSHOP_PIXEL_SCALE;

export function pixelPainter(ctx: CanvasRenderingContext2D) {
  const rect = (x: number, y: number, w: number, h: number, color: string) => {
    ctx.fillStyle = color;
    ctx.fillRect(snap(x), snap(y), snap(w), snap(h));
  };
  const line = (points: Point[], color: string, width = pixel) => {
    ctx.fillStyle = color;
    const size = Math.max(1, Math.round(width * WORKSHOP_PIXEL_SCALE));
    for (let i = 1; i < points.length; i++) {
      let x = Math.round(points[i - 1][0] * WORKSHOP_PIXEL_SCALE);
      let y = Math.round(points[i - 1][1] * WORKSHOP_PIXEL_SCALE);
      const ex = Math.round(points[i][0] * WORKSHOP_PIXEL_SCALE), ey = Math.round(points[i][1] * WORKSHOP_PIXEL_SCALE);
      const dx = Math.abs(ex - x), dy = -Math.abs(ey - y), sx = x < ex ? 1 : -1, sy = y < ey ? 1 : -1;
      let error = dx + dy;
      for (;;) {
        ctx.fillRect((x - Math.floor(size / 2)) * pixel, (y - Math.floor(size / 2)) * pixel, size * pixel, size * pixel);
        if (x === ex && y === ey) break;
        const e = 2 * error;
        if (e >= dy) { error += dy; x += sx; }
        if (e <= dx) { error += dx; y += sy; }
      }
    }
  };
  const poly = (points: Point[], fill: string, stroke?: string) => {
    const top = Math.floor(Math.min(...points.map(p => p[1])) * WORKSHOP_PIXEL_SCALE);
    const bottom = Math.ceil(Math.max(...points.map(p => p[1])) * WORKSHOP_PIXEL_SCALE);
    ctx.fillStyle = fill;
    for (let row = top; row < bottom; row++) {
      const y = (row + .5) * pixel;
      const intersections: number[] = [];
      for (let i = 0, j = points.length - 1; i < points.length; j = i++) {
        const a = points[i], b = points[j];
        if ((a[1] > y) !== (b[1] > y)) intersections.push(a[0] + (y - a[1]) * (b[0] - a[0]) / (b[1] - a[1]));
      }
      intersections.sort((a, b) => a - b);
      for (let i = 0; i < intersections.length; i += 2) {
        const left = Math.round(intersections[i] * WORKSHOP_PIXEL_SCALE);
        const right = Math.round(intersections[i + 1] * WORKSHOP_PIXEL_SCALE);
        ctx.fillRect(left * pixel, row * pixel, (right - left) * pixel, pixel);
      }
    }
    if (stroke) line([...points, points[0]], stroke);
  };
  const ellipse = (x: number, y: number, rx: number, ry: number, color: string) => {
    ctx.fillStyle = color;
    for (let row = Math.floor(-ry * 2); row <= Math.ceil(ry * 2); row++) {
      const dy = row * pixel;
      const extent = rx * Math.sqrt(Math.max(0, 1 - (dy / ry) ** 2));
      if (extent > 0) rect(x - extent, y + dy, extent * 2, pixel, color);
    }
  };
  return { rect, line, poly, ellipse };
}

export type PixelPainter = ReturnType<typeof pixelPainter>;
