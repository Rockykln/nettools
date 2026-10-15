// Small wrapper around the Workers Cache API for JSON-serializable lookup results.
// The cache is per Cloudflare data center; misses simply recompute.

const KEY_PREFIX = 'https://cache.nettools.invalid/';

export async function cachedJson<T>(key: string, ttl: (value: T) => number, produce: () => Promise<T>): Promise<T> {
  // Absent outside the Workers runtime (e.g. unit tests).
  const cache = typeof caches === 'undefined' ? null : caches.default;
  const req = new Request(KEY_PREFIX + encodeURIComponent(key));
  try {
    const hit = await cache?.match(req);
    if (hit) return await hit.json<T>();
  } catch {
    // A broken cache entry is treated as a miss.
  }
  const value = await produce();
  const seconds = Math.floor(ttl(value));
  if (cache && Number.isFinite(seconds) && seconds > 0) {
    try {
      await cache.put(req, new Response(JSON.stringify(value), {
        headers: { 'content-type': 'application/json', 'cache-control': `public, max-age=${seconds}` },
      }));
    } catch {
      // Caching is an optimization only.
    }
  }
  return value;
}
