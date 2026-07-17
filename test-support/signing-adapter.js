export function createSigningAdapter() {
  return {
    async loadJwks() { return { keys: [] }; },
    async sign() { return new Uint8Array(); },
    async rotate() {},
  };
}
