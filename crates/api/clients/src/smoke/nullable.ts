// Compile-time proof that the generated TypeScript model can say what a write of an event says (RFC 7396, docs/api.md):
// `null` removes a field, and a member that is left out keeps its stored value. The two must be told apart, so the type
// of `location` has to admit `null` and the member has to be optional. `tsc -p tsconfig.json` fails here when it does
// not.
import type { EventView } from "../../target/generated/typescript/models/index";

/** `location` is removed: `null` is a value of the member. */
export const removal: EventView = { summary: "Standup", location: null };

/** `description` is not mentioned: the member may be left out. */
export const untouched: EventView = { summary: "Standup" };
