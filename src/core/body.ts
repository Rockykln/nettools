// Reads a response body up to `max` bytes, so a huge or endless response cannot exhaust memory.
export async function readCapped(body: ReadableStream<Uint8Array> | null, max: number): Promise<Uint8Array> {
  if (!body) return new Uint8Array(0);
  const reader = body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  for (;;) {
    const { value, done } = await reader.read();
    if (done) break;
    chunks.push(value);
    size += value.byteLength;
    if (size >= max) {
      await reader.cancel().catch(() => {});
      break;
    }
  }
  // The last chunk can overshoot the cap; never return more than `max` bytes.
  const out = new Uint8Array(Math.min(size, Math.max(0, max)));
  let off = 0;
  for (const c of chunks) {
    if (off >= out.byteLength) break;
    const part = c.byteLength > out.byteLength - off ? c.subarray(0, out.byteLength - off) : c;
    out.set(part, off);
    off += part.byteLength;
  }
  return out;
}

export async function readJsonCapped<T>(res: Response, max: number): Promise<T> {
  const bytes = await readCapped(res.body, max + 1);
  if (bytes.byteLength > max) throw new Error('Response too large');
  return JSON.parse(new TextDecoder().decode(bytes)) as T;
}
