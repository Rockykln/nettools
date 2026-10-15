// Unit tests run in Node, where the Workers socket API does not exist.
export function connect(): never {
  throw new Error('cloudflare:sockets is not available in unit tests');
}
