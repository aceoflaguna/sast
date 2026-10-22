import { defineQuery } from "../src/query";
import { callRules, type CallRule } from "./_lib";

const SECURITY_NAME = /(token|secret|passw|pwd|apikey|api_key|nonce|salt|otp|csrf|session|auth|reset|verif|jwt|credential|private)/i;

export default defineQuery({
  id: "insecure-random",
  title: "Non-cryptographic randomness for a secret",
  severity: "medium",
  cwe: "CWE-338",
  description: "A predictable PRNG feeds a value whose name suggests a token/secret/password.",
  run(ctx) {
    const { $, profile } = ctx;
    // a rule only fires when the surrounding assignment target or enclosing function has a security-sensitive name
    const sensitive = (n: any) => {
      const p = profile(n);
      const asg = $(n).closest("Assign").get(0) as any;
      if (asg) for (const a of [p.assign(asg)].flat().filter(Boolean) as any[]) if (a.targets.some((t: any) => SECURITY_NAME.test(p.pathOf(t) ?? t.text))) return true;
      const fn = $(n).closest("Func").get(0) as any;
      return !!fn && SECURITY_NAME.test(p.func(fn)?.name ?? "");
    };
    const r = (callee: RegExp, extra?: (n: any) => boolean): CallRule => ({ callee, when: (n) => (extra ? extra(n) : true) && sensitive(n) });
    callRules(ctx, {
      javascript: [r(/^Math\.random$/)],
      python: [r(/^random\.(random|randint|choice|choices|getrandbits|randrange|sample|uniform)$/)],
      php: [r(/^(rand|mt_rand|uniqid|lcg_value|array_rand|str_shuffle)$/)],
      java: [r(/^(Math\.random|new Random|ThreadLocalRandom\.current)$/)],
      go: [r(/^rand\.(Int|Intn|Int31|Int31n|Int63|Int63n|Float32|Float64|Read|Perm)$/, (n) => n.tree.source.includes('"math/rand')) ],
      csharp: [r(/^new Random$/)],
      ruby: [r(/^(rand|Kernel\.rand|Random\.(rand|new))$/)],
    }, (_r, callee) => `Predictable RNG (${callee}) used for a secret; use a CSPRNG (crypto.randomBytes / secrets / SecureRandom / RandomNumberGenerator).`);
  },
});
