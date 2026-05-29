// Chio lineage viewer.
//
// Vanilla ES module. NO import map, NO bundler, NO transpiler step.
// Loads a single JSON file matching `chio.lineage.graph/v1` and renders
// the nodes/edges tables. Designed to read the output of:
//
//   chio lineage query --emit demo --json > lineage.json
//
// The viewer keeps the evidence_class on every row so reviewers can see
// at a glance whether an edge is asserted, observed, or verified.

const SCHEMA_VERSION = "chio.lineage.graph/v1";

const SAMPLE_GRAPH = Object.freeze({
  schema_version: SCHEMA_VERSION,
  nodes: [
    {
      id: "cap:cap.read",
      kind: "capability",
      evidence_class: "observed",
      label: "cap.read",
    },
    {
      id: "tool:r1:fs.read",
      kind: "tool_call",
      evidence_class: "observed",
      label: "fs.read",
    },
    {
      id: "rcpt:r1",
      kind: "receipt",
      evidence_class: "verified",
      label: "r1",
    },
  ],
  edges: [
    {
      from: "cap:cap.read",
      to: "tool:r1:fs.read",
      kind: "capability_to_guard",
      evidence_class: "observed",
    },
    {
      from: "tool:r1:fs.read",
      to: "rcpt:r1",
      kind: "tool_call_to_receipt",
      evidence_class: "verified",
    },
  ],
});

function clearTable(tbody) {
  while (tbody.firstChild) {
    tbody.removeChild(tbody.firstChild);
  }
}

function evidenceClassName(value) {
  if (value === "asserted") return "evidence-asserted";
  if (value === "observed") return "evidence-observed";
  if (value === "verified") return "evidence-verified";
  return "";
}

function renderGraph(graph) {
  const status = document.querySelector("#status");
  if (graph.schema_version !== SCHEMA_VERSION) {
    status.textContent =
      "Refusing to render: schema_version mismatch. Expected " +
      SCHEMA_VERSION +
      ", got " +
      graph.schema_version;
    return;
  }

  const nodes = Array.isArray(graph.nodes) ? graph.nodes : [];
  const edges = Array.isArray(graph.edges) ? graph.edges : [];
  const truncated = graph.truncated;

  let summary = "Loaded " + nodes.length + " nodes, " + edges.length + " edges.";
  if (truncated && truncated.truncated === true) {
    summary +=
      " Truncated at depth " +
      truncated.depth_reached +
      " (limit " +
      truncated.limit +
      ").";
  }
  status.textContent = summary;

  const nodesBody = document.querySelector("#nodes-table tbody");
  clearTable(nodesBody);
  for (const n of nodes) {
    const tr = document.createElement("tr");
    const cells = [
      n.id || "",
      n.kind || "",
      n.evidence_class || "",
      n.tenant_id || "",
      n.label || "",
    ];
    cells.forEach((value, idx) => {
      const td = document.createElement("td");
      td.textContent = value;
      if (idx === 2) td.className = evidenceClassName(value);
      tr.appendChild(td);
    });
    nodesBody.appendChild(tr);
  }

  const edgesBody = document.querySelector("#edges-table tbody");
  clearTable(edgesBody);
  for (const e of edges) {
    const tr = document.createElement("tr");
    const cells = [e.from || "", e.to || "", e.kind || "", e.evidence_class || ""];
    cells.forEach((value, idx) => {
      const td = document.createElement("td");
      td.textContent = value;
      if (idx === 3) td.className = evidenceClassName(value);
      tr.appendChild(td);
    });
    edgesBody.appendChild(tr);
  }
}

function init() {
  const fileInput = document.querySelector("#file-input");
  if (fileInput) {
    fileInput.addEventListener("change", function (event) {
      const file = event.target.files && event.target.files[0];
      if (!file) return;
      const reader = new FileReader();
      reader.addEventListener("load", function () {
        try {
          const graph = JSON.parse(String(reader.result));
          renderGraph(graph);
        } catch (err) {
          const status = document.querySelector("#status");
          status.textContent = "Failed to parse JSON: " + err;
        }
      });
      reader.readAsText(file);
    });
  }
  const loadSample = document.querySelector("#load-sample");
  if (loadSample) {
    loadSample.addEventListener("click", function () {
      renderGraph(SAMPLE_GRAPH);
    });
  }
}

init();
