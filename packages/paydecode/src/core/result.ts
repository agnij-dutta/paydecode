// Constructor for the public Decoded result: drops empty sections and sorts/dedupes flags.
import { sortFlags } from "./format.js";
import type { Decoded, Flag, Section } from "../types.js";

export function make(
  kind: string,
  title: string,
  summary: string,
  sections: Section[],
  flags: Flag[],
  raw: unknown,
  children?: Decoded[],
): Decoded {
  const d: Decoded = { kind, title, summary, sections: sections.filter((s) => s.fields.length), flags: sortFlags(flags), raw };
  if (children && children.length) d.children = children;
  return d;
}
