import { ROLE_IDS, type Role } from "./setup-code";
import type { Document, Selection } from "./schema";
export type WorkshopNavigation = {
  open: boolean;
  panel: "inspect" | "setup" | "install" | "revise";
  selection: Selection;
  document: Document;
};
export const OVERVIEW: WorkshopNavigation = {
  open: false,
  panel: "inspect",
  selection: { kind: "role", role: "implementation" },
  document: "changes",
};
export function readWorkshopNavigation(url: URL): WorkshopNavigation {
  if (
    url.searchParams.has("integration") ||
    ["#integrations", "#systems", "#build-main"].includes(url.hash)
  )
    return OVERVIEW;
  const open =
    url.searchParams.get("workshop") === "software-factory" ||
    ["#workshop", "#mission", "#start", "#adapt"].includes(url.hash);
  const role = url.searchParams.get("role");
  const selection: Selection =
    role === "project"
      ? { kind: "project" }
      : {
          kind: "role",
          role: ROLE_IDS.includes(role as Role)
            ? (role as Role)
            : "implementation",
        };
  const document = url.searchParams.get("view");
  const panel = url.searchParams.get("panel");
  return {
    open,
    selection,
    document: ["changes", "tests", "source"].includes(document ?? "")
      ? (document as Document)
      : "changes",
    panel:
      url.hash === "#start" || panel === "setup"
        ? "setup"
        : url.hash === "#adapt" || panel === "revise"
          ? "revise"
          : "inspect",
  };
}
export function workshopUrl(url: URL, state: WorkshopNavigation): URL {
  const next = new URL(url);
  for (const key of ["workshop", "role", "view", "panel"])
    next.searchParams.delete(key);
  if (state.open) {
    next.searchParams.delete("integration");
    next.searchParams.delete("category");
    next.searchParams.set("workshop", "software-factory");
    next.searchParams.set(
      "role",
      state.selection.kind === "project" ? "project" : state.selection.role,
    );
    next.searchParams.set("view", state.document);
    if (state.panel !== "inspect")
      next.searchParams.set(
        "panel",
        state.panel === "install" ? "setup" : state.panel,
      );
    next.hash = "workshop";
  } else if (["#workshop", "#mission", "#start", "#adapt"].includes(next.hash))
    next.hash = "";
  return next;
}
