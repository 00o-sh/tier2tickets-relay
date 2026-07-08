import type { Env } from "../src/types.js";

// Tell the vitest-pool-workers runtime the shape of `env` exposed by "cloudflare:test".
declare module "cloudflare:test" {
  interface ProvidedEnv extends Env {}
}
