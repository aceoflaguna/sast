import type { Profile } from "./types";
import { javascript } from "./javascript";
import { python } from "./python";
import { php } from "./php";
import { java } from "./java";
import { go } from "./go";
import { csharp } from "./csharp";
import { ruby } from "./ruby";

const byParser: Record<string, Profile> = { javascript, typescript: javascript, tsx: javascript, python, php, java, go, csharp, ruby };
export function profileFor(parserLanguage: string): Profile {
  const p = byParser[parserLanguage];
  if (!p) throw new Error("No profile for language " + parserLanguage);
  return p;
}
export const profiles = { javascript, python, php, java, go, csharp, ruby };
export type { Profile, CallInfo, AssignInfo, FuncInfo } from "./types";
