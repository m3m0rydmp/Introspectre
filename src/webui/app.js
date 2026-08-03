/* Introspectre visualizer frontend.
 *
 * Fetches the analysis payload from `GET /api/schema` and renders an interactive
 * WebGL attack-surface graph with Sigma.js + graphology. The camera is Sigma's
 * native camera (wheel = zoom, drag = pan); node clicks only select/inspect — they
 * never drive the zoom, which is what previously made clicking jump the viewport.
 */
(function () {
    "use strict";

    // ---- Palette (mirrors app.css) -----------------------------------------
    const RISK_COLOR = {
        critical: "#ff3b6b", high: "#ff7b39", medium: "#ffcf3f",
        low: "#63d2ff", info: "#6ee7b7", neutral: "#5a6580",
    };
    const KIND_COLOR = {
        OBJECT: "#39d3ff", ENUM: "#b47cff", INPUT_OBJECT: "#ffcf3f",
        INTERFACE: "#6ee7b7", UNION: "#ff7bd5", SCALAR: "#5a6580", UNKNOWN: "#5a6580",
    };
    const SCALARISH = new Set(["SCALAR", "ENUM"]);

    // ---- State -------------------------------------------------------------
    let DATA = null;
    let masterNodes = [];           // all nodes from payload
    let masterEdges = [];           // all edges (with synthetic ids)
    const nodeById = new Map();
    const outAdj = new Map();        // id -> [edge] (source === id)
    const inAdj = new Map();         // id -> [edge] (target === id)

    let graph = null;                // graphology Graph (visible subset)
    let renderer = null;             // Sigma instance
    let hideScalars = true;
    let isolateMode = false;
    let selectedNode = null;
    let hoveredNode = null;
    let draggedNode = null;          // node currently being dragged (or null)

    // ---- Boot --------------------------------------------------------------
    fetch("/api/schema")
        .then((r) => { if (!r.ok) throw new Error("HTTP " + r.status); return r.json(); })
        .then(init)
        .catch((err) => {
            const el = document.getElementById("loading");
            el.innerHTML = '<span style="color:#ff7b39">Failed to load /api/schema: ' + escapeHtml(String(err)) + "</span>";
        });

    // One-time setup: build the renderer + wire controls once, then load the first payload.
    // Switching targets reuses `loadPayload` without rebuilding the renderer.
    function init(payload) {
        document.getElementById("loading").style.display = "none";
        buildRenderer();
        wireToolbar();
        wireTabs();
        wireContextMenu();
        wireGuide();
        loadTargets();
        loadPayload(payload);
    }

    // (Re)load an analysis payload into the existing renderer + panels. Used for the initial
    // fetch and for every target switch.
    function loadPayload(payload) {
        DATA = payload;

        // Reset per-target state and re-index the master graph.
        nodeById.clear(); outAdj.clear(); inAdj.clear();
        selectedNode = null; hoveredNode = null; draggedNode = null;
        closeDetail();

        masterNodes = (payload.graph && payload.graph.nodes) || [];
        masterEdges = ((payload.graph && payload.graph.edges) || []).map((e, i) => Object.assign({ _id: "e" + i }, e));
        masterNodes.forEach((n) => nodeById.set(n.id, n));
        masterEdges.forEach((e) => {
            if (!outAdj.has(e.source)) outAdj.set(e.source, []);
            if (!inAdj.has(e.target)) inAdj.set(e.target, []);
            outAdj.get(e.source).push(e);
            inAdj.get(e.target).push(e);
        });

        // Header
        document.getElementById("endpoint-url").textContent = payload.source || "";
        const b = document.getElementById("fingerprint-badge");
        if (payload.serverFingerprint) {
            b.textContent = payload.serverFingerprint;
            b.style.display = "inline-block";
        } else {
            b.style.display = "none";
        }

        renderFindings();
        renderSeeds();
        renderSchema();
        resetView(); // root operations + direct neighbors
    }

    // ---- Target switcher ---------------------------------------------------
    function loadTargets() {
        const sel = byId("target-select");
        if (!sel) return;
        fetch("/api/targets")
            .then((r) => (r.ok ? r.json() : []))
            .then((targets) => {
                if (!targets.length) { sel.style.display = "none"; return; }
                sel.innerHTML = targets.map((t) =>
                    `<option value="${escapeAttr(String(t.id))}"${t.current ? " selected" : ""}>${escapeHtml(t.name)} · ${escapeHtml((t.scannedAt || "").slice(0, 10))}</option>`).join("");
                sel.onchange = () => switchTarget(sel.value);
            })
            .catch(() => { sel.style.display = "none"; });
    }

    function switchTarget(id) {
        const overlay = document.getElementById("loading");
        overlay.style.display = "flex";
        overlay.querySelector("span") && (overlay.querySelector("span").textContent = "Loading target…");
        fetch("/api/targets/" + encodeURIComponent(id) + "/schema")
            .then((r) => { if (!r.ok) throw new Error("HTTP " + r.status); return r.json(); })
            .then((payload) => { overlay.style.display = "none"; loadPayload(payload); })
            .catch((err) => { overlay.style.display = "none"; toast("Could not load target: " + err); });
    }

    // ---- Graph construction ------------------------------------------------
    function buildRenderer() {
        graph = new graphology.Graph({ multi: true, type: "directed" });

        const R = Sigma.rendering;
        // Bordered node program: fill = risk color, ring = kind color. Needs no
        // texture, so a node can never render invisible.
        const Bordered = R.createNodeBorderProgram({
            borders: [
                { size: { value: 0.16 }, color: { attribute: "borderColor" } },
                { size: { fill: true }, color: { attribute: "color" } },
            ],
        });

        const settings = {
            defaultEdgeType: "arrow",
            renderLabels: true,
            labelColor: { color: "#d7e0ea" },
            labelFont: 'ui-monospace, "Cascadia Code", "JetBrains Mono", Consolas, monospace',
            labelSize: 12,
            labelRenderedSizeThreshold: 5,
            labelDensity: 0.7,
            labelGridCellSize: 60,
            defaultEdgeColor: "#33404f",
            minCameraRatio: 0.05,
            maxCameraRatio: 14,
            allowInvalidContainer: true,
            nodeProgramClasses: { bordered: Bordered },
            defaultNodeType: "bordered",
            nodeReducer,
            edgeReducer,
        };

        try {
            renderer = new Sigma(graph, document.getElementById("graph"), settings);
        } catch (err) {
            console.warn("Sigma init failed with arrow edges; retrying with line edges", err);
            settings.defaultEdgeType = "line";
            renderer = new Sigma(graph, document.getElementById("graph"), settings);
        }

        // --- Interactions (camera stays native: wheel zoom, drag pan) ---
        renderer.on("clickNode", ({ node }) => selectNode(node));
        renderer.on("enterNode", ({ node }) => { hoveredNode = node; renderer.refresh(); document.body.style.cursor = "pointer"; });
        renderer.on("leaveNode", () => { hoveredNode = null; renderer.refresh(); document.body.style.cursor = "default"; });
        renderer.on("clickStage", () => { closeDetail(); hideContextMenu(); });
        renderer.on("rightClickNode", (e) => {
            e.preventSigmaDefault && e.preventSigmaDefault();
            const orig = e.event && e.event.original;
            if (orig) { orig.preventDefault(); showContextMenu(e.node, orig.clientX, orig.clientY); }
        });
        // Suppress the browser context menu over the canvas so ours is the only one.
        document.getElementById("graph").addEventListener("contextmenu", (ev) => ev.preventDefault());

        // --- Node dragging (independent of the camera) ---
        // Start on a mousedown while a node is hovered (enter/leaveNode keep `hoveredNode`
        // current). During the drag we write the node's graph-space coords from the pointer
        // and preventSigmaDefault() so the camera doesn't pan. Wheel/double-click zoom stay
        // native and untouched.
        const captor = renderer.getMouseCaptor();
        let dragOffset = { x: 0, y: 0 };
        captor.on("mousedown", (e) => {
            if (!hoveredNode) return;
            draggedNode = hoveredNode;
            // Record where on the node the grab happened, so the node tracks the cursor 1:1
            // (no snap-to-center jump, and the camera never pans underneath it).
            const g = renderer.viewportToGraph(e);
            dragOffset = {
                x: graph.getNodeAttribute(draggedNode, "x") - g.x,
                y: graph.getNodeAttribute(draggedNode, "y") - g.y,
            };
            graph.setNodeAttribute(draggedNode, "highlighted", true);
            document.body.style.cursor = "grabbing";
            e.preventSigmaDefault();
        });
        captor.on("mousemovebody", (e) => {
            if (!draggedNode) return;
            const g = renderer.viewportToGraph(e);
            graph.setNodeAttribute(draggedNode, "x", g.x + dragOffset.x);
            graph.setNodeAttribute(draggedNode, "y", g.y + dragOffset.y);
            e.preventSigmaDefault();
            if (e.original) { e.original.preventDefault(); e.original.stopPropagation(); }
        });
        const endDrag = () => {
            if (!draggedNode) return;
            graph.removeNodeAttribute(draggedNode, "highlighted");
            draggedNode = null;
            document.body.style.cursor = hoveredNode ? "pointer" : "default";
        };
        captor.on("mouseup", endDrag);
        captor.on("mouseupbody", endDrag);

        // --- Level-of-Detail: drop labels when zoomed out ---
        // Rendering thousands of label glyphs every frame is the main cost on large
        // graphs. When the camera zooms out past LOD_RATIO the whole view is a cluster
        // overview where individual labels are unreadable anyway, so we turn label
        // rendering off entirely; zooming back in restores them. We only call
        // setSetting when the state actually flips, to avoid redundant refreshes.
        const LOD_RATIO = 1.6;
        let labelsOn = true;
        const applyLod = () => {
            const ratio = renderer.getCamera().ratio;
            const shouldShow = ratio <= LOD_RATIO;
            if (shouldShow !== labelsOn) {
                labelsOn = shouldShow;
                renderer.setSetting("renderLabels", labelsOn);
            }
        };
        renderer.getCamera().on("updated", applyLod);
        applyLod();
    }

    function nodeReducer(id, data) {
        const res = Object.assign({}, data);
        if (isolateMode && selectedNode) {
            const keep = id === selectedNode || isNeighbor(id, selectedNode);
            if (!keep) { res.hidden = true; return res; }
        }
        const focus = hoveredNode || selectedNode;
        if (focus && id !== focus && !isNeighbor(id, focus)) {
            res.color = fade(res.color);
            res.borderColor = fade(res.borderColor);
            res.label = "";
        }
        if (id === selectedNode) { res.highlighted = true; res.zIndex = 2; }
        return res;
    }

    function edgeReducer(id, data) {
        const res = Object.assign({}, data);
        const focus = hoveredNode || selectedNode;
        if (focus) {
            const [s, t] = [graph.source(id), graph.target(id)];
            if (s !== focus && t !== focus) { res.color = "#1c2530"; res.hidden = isolateMode; }
            else { res.color = "#5f7089"; res.zIndex = 2; }
        }
        return res;
    }

    // ---- Visible-graph mutation -------------------------------------------
    function rebuild(nodeIds, edgeList) {
        graph.clear();
        const idset = new Set(nodeIds);
        nodeIds.forEach((id) => {
            const n = nodeById.get(id);
            if (!n) return;
            graph.addNode(id, nodeAttrs(n));
        });
        (edgeList || []).forEach((e) => {
            if (idset.has(e.source) && idset.has(e.target) && !graph.hasEdge(e._id)) {
                try {
                    graph.addEdgeWithKey(e._id, e.source, e.target, {
                        label: e.label, size: Math.min(1 + (e.weight || 1) * 0.2, 3),
                        color: e.isDeprecated ? "#6b4a2a" : "#33404f", type: graph.type === "directed" ? "arrow" : "line",
                    });
                } catch (_) { /* ignore parallel/self edge issues */ }
            }
        });
        layout();
        updateCounts();
        renderer && renderer.refresh();
    }

    function nodeAttrs(n) {
        const size = n.isRoot ? 14 : SCALARISH.has(n.kind) ? 5 : 8;
        return {
            label: n.label,
            x: Math.random(), y: Math.random(),
            size,
            color: RISK_COLOR[n.risk] || RISK_COLOR.neutral,
            borderColor: KIND_COLOR[n.kind] || KIND_COLOR.UNKNOWN,
            type: "bordered",
        };
    }

    function layout(light) {
        if (graph.order === 0) return;
        try {
            const fa2 = graphologyLibrary.layoutForceAtlas2;
            // `light`: nodes were pre-seeded near their anchor (chunked expand), so a short
            // pass is enough to relax them — keeps the final settle off the freeze path.
            const iterations = light
                ? (graph.order > 400 ? 40 : 80)
                : (graph.order > 400 ? 120 : graph.order > 120 ? 240 : 400);
            const settings = fa2.inferSettings(graph);
            settings.gravity = 1.2;
            settings.scalingRatio = 12;
            fa2.assign(graph, { iterations, settings });
        } catch (err) {
            console.warn("layout failed", err);
        }
        // Fit after layout settles.
        requestAnimationFrame(fitView);
    }

    // ---- View actions ------------------------------------------------------
    function resetView() {
        selectedNode = null;
        let roots = masterNodes.filter((n) => n.isRoot);
        if (roots.length === 0) roots = masterNodes.slice(0, Math.min(1, masterNodes.length));
        // Roots + their direct neighbors so the initial canvas is meaningful.
        const ids = new Set();
        const edges = [];
        roots.forEach((r) => {
            ids.add(r.id);
            (outAdj.get(r.id) || []).forEach((e) => {
                if (hideScalars && isScalarish(e.target)) return;
                ids.add(e.target); edges.push(e);
            });
        });
        rebuild([...ids], edges);
    }

    function showAll() {
        if (masterNodes.length > 160 &&
            !confirm(`This schema has ${masterNodes.length} types and ${masterEdges.length} relations. Rendering everything may be heavy. Continue?`)) return;
        let nodes = masterNodes, edges = masterEdges;
        if (hideScalars) {
            nodes = masterNodes.filter((n) => !SCALARISH.has(n.kind));
            const keep = new Set(nodes.map((n) => n.id));
            edges = masterEdges.filter((e) => keep.has(e.source) && keep.has(e.target));
        }
        rebuild(nodes.map((n) => n.id), edges);
    }

    function expandNode(id, deep) {
        const current = new Set(graph.nodes());
        const edges = collectVisibleEdges();
        const frontier = [id];
        const seen = new Set();
        while (frontier.length) {
            const cur = frontier.shift();
            if (seen.has(cur)) continue;
            seen.add(cur);
            (outAdj.get(cur) || []).forEach((e) => {
                if (hideScalars && isScalarish(e.target)) return;
                current.add(e.target); edges.push(e);
                if (deep && !seen.has(e.target)) frontier.push(e.target);
            });
        }
        current.add(id);
        const nodeIds = [...current];
        const dedupedEdges = dedupeEdges(edges);
        // A shallow expand adds only the direct neighbours — cheap, do it in one pass.
        // A deep "expand all" can pull in thousands of nodes; inserting them (plus the
        // full forceAtlas2 relayout) in a single synchronous rebuild freezes the tab.
        // Above a threshold, add them in requestAnimationFrame-batched chunks so each
        // frame's work is bounded and the graph visibly grows instead of hanging.
        const CHUNK_THRESHOLD = 600;
        if (deep && nodeIds.length > CHUNK_THRESHOLD) {
            chunkedRebuild(nodeIds, dedupedEdges, id);
        } else {
            rebuild(nodeIds, dedupedEdges);
            renderer.getCamera().animate(nodeCamera(id), { duration: 350 });
        }
    }

    // Rebuild the graph by adding nodes/edges in animation-frame batches instead of one
    // blocking pass. New nodes are seeded near an anchor so the final layout can run with
    // a reduced iteration count (positions are already roughly settled), keeping the whole
    // operation off the "freeze the main thread" path. (Sigma/graphology run on the main
    // thread — there's no Web Worker option here — so rAF chunking is the practical fix.)
    function chunkedRebuild(nodeIds, edgeList, anchorId) {
        graph.clear();
        const idset = new Set(nodeIds);
        const anchor = nodeById.get(anchorId);
        const ax = 0, ay = 0; // relayout re-centres; jitter around origin is fine.
        const relevantEdges = (edgeList || []).filter((e) => idset.has(e.source) && idset.has(e.target));
        const BATCH = 400;
        let ni = 0, ei = 0;
        toast("Expanding " + (nodeIds.length - 1) + " nodes…");
        function addNodesFrame() {
            let added = 0;
            while (ni < nodeIds.length && added < BATCH) {
                const id = nodeIds[ni++];
                const n = nodeById.get(id);
                if (n && !graph.hasNode(id)) {
                    const attrs = nodeAttrs(n);
                    // Seed near the anchor so FA2 has a warm start (cheap final layout).
                    attrs.x = ax + (Math.random() - 0.5) * 0.6;
                    attrs.y = ay + (Math.random() - 0.5) * 0.6;
                    graph.addNode(id, attrs);
                }
                added++;
            }
            renderer && renderer.refresh();
            if (ni < nodeIds.length) { requestAnimationFrame(addNodesFrame); return; }
            requestAnimationFrame(addEdgesFrame);
        }
        function addEdgesFrame() {
            let added = 0;
            while (ei < relevantEdges.length && added < BATCH) {
                const e = relevantEdges[ei++];
                if (!graph.hasEdge(e._id)) {
                    try {
                        graph.addEdgeWithKey(e._id, e.source, e.target, {
                            label: e.label, size: Math.min(1 + (e.weight || 1) * 0.2, 3),
                            color: e.isDeprecated ? "#6b4a2a" : "#33404f",
                            type: graph.type === "directed" ? "arrow" : "line",
                        });
                    } catch (_) { /* ignore parallel/self edge issues */ }
                }
                added++;
            }
            renderer && renderer.refresh();
            if (ei < relevantEdges.length) { requestAnimationFrame(addEdgesFrame); return; }
            // Final light layout: nodes are pre-seeded, so fewer iterations settle them.
            requestAnimationFrame(() => {
                layout(true);
                updateCounts();
                renderer && renderer.refresh();
                if (renderer.getNodeDisplayData(anchorId)) {
                    renderer.getCamera().animate(nodeCamera(anchorId), { duration: 350 });
                }
                void anchor;
            });
        }
        requestAnimationFrame(addNodesFrame);
    }

    function traceToRoot(id) {
        // BFS backward along incoming edges until a root type is reached.
        const parent = new Map();
        const q = [id]; const seen = new Set([id]);
        let hitRoot = null;
        while (q.length) {
            const cur = q.shift();
            const n = nodeById.get(cur);
            if (n && n.isRoot && cur !== id) { hitRoot = cur; break; }
            (inAdj.get(cur) || []).forEach((e) => {
                if (!seen.has(e.source)) { seen.add(e.source); parent.set(e.source, e); q.push(e.source); }
            });
        }
        const current = new Set(graph.nodes());
        const edges = collectVisibleEdges();
        current.add(id);
        if (hitRoot) {
            let step = hitRoot;
            // Walk parent chain from root back to id (edges point child->... we stored source->edge)
            const guard = new Set();
            while (step && step !== id && !guard.has(step)) {
                guard.add(step);
                const e = parent.get(step);
                if (!e) break;
                current.add(e.source); current.add(e.target); edges.push(e);
                step = e.target;
            }
        } else {
            toast("No path to a root operation was found for " + id + ".");
        }
        rebuild([...current], dedupeEdges(edges));
    }

    function hideNode(id) {
        const nodes = graph.nodes().filter((n) => n !== id);
        rebuild(nodes, collectVisibleEdges().filter((e) => e.source !== id && e.target !== id));
        if (selectedNode === id) closeDetail();
    }

    function focusNode(id) {
        if (!graph.hasNode(id)) {
            // Bring it in with its neighbors first.
            const cur = new Set(graph.nodes()); cur.add(id);
            const edges = collectVisibleEdges();
            (outAdj.get(id) || []).forEach((e) => { cur.add(e.target); edges.push(e); });
            (inAdj.get(id) || []).forEach((e) => { cur.add(e.source); edges.push(e); });
            rebuild([...cur], dedupeEdges(edges));
        }
        selectNode(id);
        if (renderer.getNodeDisplayData(id)) renderer.getCamera().animate(nodeCamera(id), { duration: 400 });
    }

    function fitView() {
        if (!renderer || graph.order === 0) return;
        const cam = renderer.getCamera();
        cam.animate({ x: 0.5, y: 0.5, ratio: 1.05, angle: 0 }, { duration: 300 });
    }

    function nodeCamera(id) {
        const d = renderer.getNodeDisplayData(id);
        return d ? { x: d.x, y: d.y, ratio: 0.4 } : { ratio: 0.6 };
    }

    // ---- Selection / detail panel -----------------------------------------
    function selectNode(id) {
        selectedNode = id;
        renderer.refresh();
        renderDetail(id);
    }

    function renderDetail(id) {
        const n = nodeById.get(id);
        if (!n) return;
        const out = outAdj.get(id) || [];
        const inc = inAdj.get(id) || [];
        const findings = findingsForType(id);

        let html = "";
        html += `<div class="detail-title">${escapeHtml(n.label)}</div>`;
        html += `<div class="detail-kind">${escapeHtml(n.kind)}${n.opType ? " · " + n.opType : ""}</div>`;
        html += `<div class="tagrow">`;
        if (n.isRoot) html += `<span class="tag auth">root</span>`;
        if (n.authRequired) html += `<span class="tag auth">auth required</span>`;
        if (n.isSensitive) html += `<span class="tag warn">sensitive fields</span>`;
        if (n.risk && n.risk !== "neutral") html += `<span class="sev-pill pill-${n.risk}">${n.risk}</span>`;
        html += `</div>`;

        if (findings.length) {
            html += `<div class="detail-section"><h4>Findings (${findings.length})</h4>`;
            findings.forEach((f) => {
                html += `<div class="rel" data-finding="${escapeAttr(f.id)}"><span class="sev-pill pill-${f.severity}">${f.severity}</span> ${escapeHtml(f.title)}</div>`;
            });
            html += `</div>`;
        }

        // A complete runnable query reaching this node from a root (non-root nodes).
        if (n.sampleQuery) {
            html += section("Sample query", codeBlock(n.sampleQuery, true));
        }
        // Enum values.
        if (n.enumValues && n.enumValues.length) {
            html += `<div class="detail-section"><h4>Enum values (${n.enumValues.length})</h4>` +
                n.enumValues.map((v) => `<div class="rel mono">${escapeHtml(v)}</div>`).join("") + `</div>`;
        }

        // Outgoing fields (skip the synthetic argument-type edges, whose labels carry "(").
        const fieldEdges = out.filter((e) => !e.label.includes("("));
        if (fieldEdges.length) {
            html += `<div class="detail-section"><h4>Fields → (${fieldEdges.length})</h4>`;
            fieldEdges.slice(0, 80).forEach((e, i) => {
                const argsig = (e.args && e.args.length) ? `(${e.args.map((a) => a.name).join(", ")})` : "";
                html += `<div class="rel" data-goto="${escapeAttr(e.target)}"><span class="arrow">${escapeHtml(e.label)}</span>${escapeHtml(argsig)} → <span class="tgt">${escapeHtml(e.target)}</span>`;
                if (e.sample) html += ` <button class="sample-toggle" data-sample="s${i}">sample</button>`;
                html += `</div>`;
                if (e.sample) html += `<div class="sample-box" id="s${i}" style="display:none">${codeBlock(e.sample, true)}</div>`;
            });
            html += `</div>`;
        }

        // Referenced by (incoming field edges; skip argument-type edges).
        const incEdges = inc.filter((e) => !e.label.includes("("));
        if (incEdges.length) {
            html += `<div class="detail-section"><h4>Referenced by (${incEdges.length})</h4>`;
            incEdges.slice(0, 40).forEach((e) => {
                html += `<div class="rel" data-goto="${escapeAttr(e.source)}"><span class="tgt">${escapeHtml(e.source)}</span>.<span class="arrow">${escapeHtml(e.label)}</span></div>`;
            });
            html += `</div>`;
        }

        const body = document.getElementById("detail-body");
        body.innerHTML = html;
        body.querySelectorAll(".rel[data-goto]").forEach((el) =>
            el.addEventListener("click", (ev) => { if (ev.target.closest(".sample-toggle")) return; focusNode(el.getAttribute("data-goto")); }));
        body.querySelectorAll("[data-finding]").forEach((el) =>
            el.addEventListener("click", () => { switchTab("findings"); openFinding(el.getAttribute("data-finding")); }));
        body.querySelectorAll(".sample-toggle").forEach((el) =>
            el.addEventListener("click", (ev) => {
                ev.stopPropagation();
                const box = document.getElementById(el.getAttribute("data-sample"));
                if (box) box.style.display = box.style.display === "none" ? "block" : "none";
            }));
        body.querySelectorAll(".copy-btn").forEach((el) =>
            el.addEventListener("click", (ev) => { ev.stopPropagation(); copyText(el.nextElementSibling.textContent, el); }));
        document.getElementById("node-detail").classList.add("open");
    }

    function closeDetail() {
        selectedNode = null;
        document.getElementById("node-detail").classList.remove("open");
        renderer && renderer.refresh();
    }

    // ---- Side panels -------------------------------------------------------
    function renderFindings() {
        const findings = DATA.findings || [];
        document.getElementById("findings-count").textContent = findings.length;
        const pane = document.getElementById("pane-findings");
        if (!findings.length) { pane.innerHTML = `<div class="empty">No findings reported.</div>`; return; }
        const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
        const sorted = findings.slice().sort((a, b) => (order[a.severity] ?? 9) - (order[b.severity] ?? 9));
        pane.innerHTML = sorted.map(findingCard).join("");
        pane.querySelectorAll("[data-fid]").forEach((el) =>
            el.addEventListener("click", () => openFinding(el.getAttribute("data-fid"))));
    }

    function findingCard(f) {
        const aff = (f.affected || []).slice(0, 4).map((a) => `<span class="mono">${escapeHtml(a)}</span>`).join("");
        return `<div class="finding sev-${f.severity}" data-fid="${escapeAttr(f.id)}">
            <div class="f-head"><span class="f-title">${escapeHtml(f.title)}</span><span class="sev-pill">${f.severity}</span></div>
            <div class="f-desc">${escapeHtml(truncate(f.description || "", 160))}</div>
            <div class="f-affected">${aff}</div>
        </div>`;
    }

    function openFinding(fid) {
        const f = (DATA.findings || []).find((x) => String(x.id) === String(fid));
        if (!f) return;
        const t = (f.templates && f.templates[0]) || null;
        let html = `<button class="detail-close" onclick="void 0" style="display:none"></button>`;
        html = `<div class="detail-title">${escapeHtml(f.title)}</div>
            <div class="tagrow"><span class="sev-pill pill-${f.severity}">${f.severity}</span>
            ${f.status ? `<span class="tag">${escapeHtml(String(f.status))}</span>` : ""}</div>`;
        if (f.description) html += section("Description", `<div class="f-desc">${escapeHtml(f.description)}</div>`);
        if (f.first_step) html += section("First step", `<div class="f-desc">${escapeHtml(f.first_step)}</div>`);
        if (f.affected && f.affected.length) html += section("Affected", f.affected.map((a) => `<div class="rel" data-goto="${escapeAttr(typeOf(a))}">${escapeHtml(a)}</div>`).join(""));
        if (t && t.literal) html += section("Query template", codeBlock(t.literal, true));
        if (f.poc) html += section("Proof of concept", codeBlock(f.poc));
        if (f.exploit_guide) html += section("Exploitation guide", codeBlock(f.exploit_guide));
        if (f.remediation) html += section("Remediation", `<div class="f-desc">${escapeHtml(f.remediation)}</div>`);
        if (f.references && f.references.length) html += section("References", f.references.map((r) => `<div class="rel"><a href="${escapeAttr(r)}" target="_blank" rel="noopener" style="color:var(--cyan)">${escapeHtml(r)}</a></div>`).join(""));

        const body = document.getElementById("detail-body");
        body.innerHTML = html;
        body.querySelectorAll("[data-goto]").forEach((el) =>
            el.addEventListener("click", () => { const id = el.getAttribute("data-goto"); if (id) focusNode(id); }));
        body.querySelectorAll(".copy-btn").forEach((el) =>
            el.addEventListener("click", () => copyText(el.nextElementSibling.textContent, el)));
        document.getElementById("node-detail").classList.add("open");
    }

    function renderSeeds() {
        const seeds = DATA.seeds || [];
        const pane = document.getElementById("pane-seeds");
        if (!seeds.length) { pane.innerHTML = `<div class="empty">No learned seed values.<br>Provide traffic with <span class="mono">--seed-traffic</span>.</div>`; return; }
        let html = `<table class="kv">`;
        seeds.forEach((s) => {
            html += `<tr><td class="k">${escapeHtml(s.field_name)}<br><span style="color:var(--text-faint);font-size:10px">${escapeHtml(s.source)}</span></td><td class="v">${escapeHtml(s.value)}</td></tr>`;
        });
        html += `</table>`;
        pane.innerHTML = html;
    }

    function renderSchema() {
        const st = DATA.stats || {};
        const pane = document.getElementById("pane-schema");
        const cells = [
            ["Types", st.total_types], ["Objects", st.object_types],
            ["Queries", st.queries], ["Mutations", st.mutations],
            ["Subscriptions", st.subscriptions], ["Enums", st.enums],
            ["Interfaces", st.interfaces], ["Unions", st.unions],
            ["Fields", st.total_fields], ["Deprecated", st.deprecated_fields],
        ];
        let html = `<div class="stat-grid">`;
        cells.forEach(([lbl, num]) => {
            html += `<div class="stat"><div class="num">${num ?? 0}</div><div class="lbl">${lbl}</div></div>`;
        });
        html += `</div>`;

        // Ecosystem is always surfaced — "undetected" rather than silently absent.
        const fp = DATA.serverFingerprint;
        html += section("Server framework",
            `<div class="mono" style="color:${fp ? "var(--cyan)" : "var(--text-faint)"}">${escapeHtml(fp || "undetected")}</div>`);

        // Full schema tree, grouped by kind (types → fields, with enum values).
        html += `<div class="detail-section"><h4>Schema tree</h4>`;
        html += `<input id="tree-filter" class="tree-filter" type="text" placeholder="Filter types…" autocomplete="off" spellcheck="false">`;
        html += `<div id="tree-root">`;
        const groups = [
            ["Query", (n) => n.opType === "query"],
            ["Mutation", (n) => n.opType === "mutation"],
            ["Subscription", (n) => n.opType === "subscription"],
            ["Objects", (n) => !n.isRoot && n.kind === "OBJECT"],
            ["Interfaces", (n) => n.kind === "INTERFACE"],
            ["Unions", (n) => n.kind === "UNION"],
            ["Inputs", (n) => n.kind === "INPUT_OBJECT"],
            ["Enums", (n) => n.kind === "ENUM"],
            ["Scalars", (n) => n.kind === "SCALAR"],
        ];
        groups.forEach(([label, pred]) => {
            const types = masterNodes.filter(pred).slice().sort((a, b) => a.label.localeCompare(b.label));
            if (!types.length) return;
            html += `<div class="tree-group"><div class="tree-grp-head">${label} <span class="tree-count">${types.length}</span></div>`;
            types.forEach((t) => { html += renderTreeType(t); });
            html += `</div>`;
        });
        html += `</div></div>`;
        pane.innerHTML = html;

        pane.querySelectorAll(".tree-type-head").forEach((el) =>
            el.addEventListener("click", (ev) => { if (ev.target.closest(".tree-goto")) return; el.parentElement.classList.toggle("open"); }));
        pane.querySelectorAll(".tree-goto").forEach((el) =>
            el.addEventListener("click", (ev) => { ev.stopPropagation(); focusNode(el.getAttribute("data-goto")); }));
        const filter = byId("tree-filter");
        if (filter) filter.addEventListener("input", () => {
            const q = filter.value.trim().toLowerCase();
            pane.querySelectorAll(".tree-type").forEach((el) => {
                el.style.display = (!q || (el.getAttribute("data-name") || "").includes(q)) ? "" : "none";
            });
        });
    }

    function renderTreeType(t) {
        const fields = (outAdj.get(t.id) || []).filter((e) => !e.label.includes("("));
        const hasChildren = fields.length || (t.enumValues && t.enumValues.length);
        let h = `<div class="tree-type" data-name="${escapeAttr(t.label.toLowerCase())}">`;
        h += `<div class="tree-type-head"><span class="tree-caret">${hasChildren ? "▸" : "·"}</span>`;
        h += `<span class="tree-goto tree-tname" data-goto="${escapeAttr(t.id)}">${escapeHtml(t.label)}</span>`;
        h += `<span class="tree-kind">${escapeHtml(t.kind)}</span></div>`;
        if (hasChildren) {
            h += `<div class="tree-children">`;
            fields.forEach((e) => {
                const argsig = (e.args && e.args.length) ? `(${e.args.map((a) => a.name).join(", ")})` : "";
                h += `<div class="tree-field"><span class="fname">${escapeHtml(e.label)}</span><span class="fargs">${escapeHtml(argsig)}</span>: <span class="tree-goto ftype" data-goto="${escapeAttr(e.target)}">${escapeHtml(e.target)}</span></div>`;
            });
            (t.enumValues || []).forEach((v) => {
                h += `<div class="tree-field"><span class="enumval">${escapeHtml(v)}</span></div>`;
            });
            h += `</div>`;
        }
        h += `</div>`;
        return h;
    }

    // ---- Search ------------------------------------------------------------
    function wireToolbar() {
        byId("btn-scalars").addEventListener("click", (e) => {
            hideScalars = !hideScalars;
            e.target.classList.toggle("active", hideScalars);
            e.target.textContent = "Scalars: " + (hideScalars ? "hidden" : "shown");
            // Re-derive current view honoring the toggle.
            const cur = graph.nodes();
            if (cur.length) rebuild(
                hideScalars ? cur.filter((id) => !isScalarish(id)) : cur,
                collectVisibleEdges());
        });
        byId("btn-isolate").addEventListener("click", (e) => {
            isolateMode = !isolateMode;
            e.target.classList.toggle("active", isolateMode);
            e.target.textContent = "Isolate: " + (isolateMode ? "on" : "off");
            renderer.refresh();
        });
        byId("btn-showall").addEventListener("click", showAll);
        byId("btn-reset").addEventListener("click", resetView);
        byId("btn-fit").addEventListener("click", fitView);

        const input = byId("search-input");
        const results = byId("search-results");
        input.addEventListener("input", () => {
            const q = input.value.trim().toLowerCase();
            if (!q) { results.classList.remove("open"); return; }
            const hits = masterNodes.filter((n) => n.label.toLowerCase().includes(q)).slice(0, 30);
            results.innerHTML = hits.map((n) =>
                `<div class="sr-item" data-goto="${escapeAttr(n.id)}">${escapeHtml(n.label)}<span class="sr-kind">${escapeHtml(n.kind)}</span></div>`).join("")
                || `<div class="sr-item" style="color:var(--text-faint)">no matches</div>`;
            results.classList.add("open");
            results.querySelectorAll("[data-goto]").forEach((el) =>
                el.addEventListener("click", () => { focusNode(el.getAttribute("data-goto")); results.classList.remove("open"); input.value = ""; }));
        });
        input.addEventListener("blur", () => setTimeout(() => results.classList.remove("open"), 150));
        document.getElementById("detail-close").addEventListener("click", closeDetail);
    }

    function wireTabs() {
        document.querySelectorAll(".tab").forEach((t) =>
            t.addEventListener("click", () => switchTab(t.getAttribute("data-tab"))));
    }
    function switchTab(name) {
        document.querySelectorAll(".tab").forEach((t) => t.classList.toggle("active", t.getAttribute("data-tab") === name));
        document.querySelectorAll(".tab-pane").forEach((p) => p.classList.toggle("active", p.id === "pane-" + name));
    }

    // ---- Context menu ------------------------------------------------------
    let ctxNode = null;
    function wireContextMenu() {
        const menu = byId("ctxmenu");
        menu.querySelectorAll(".ctx-item").forEach((item) =>
            item.addEventListener("click", () => {
                const act = item.getAttribute("data-act");
                if (!ctxNode) return;
                if (act === "expand") expandNode(ctxNode, false);
                else if (act === "expandall") expandNode(ctxNode, true);
                else if (act === "trace") traceToRoot(ctxNode);
                else if (act === "hide") hideNode(ctxNode);
                hideContextMenu();
            }));
        document.addEventListener("click", (e) => { if (!menu.contains(e.target)) hideContextMenu(); });
    }
    function showContextMenu(node, x, y) {
        ctxNode = node;
        const menu = byId("ctxmenu");
        menu.style.left = x + "px";
        menu.style.top = y + "px";
        menu.classList.add("open");
    }
    function hideContextMenu() { byId("ctxmenu").classList.remove("open"); ctxNode = null; }

    // ---- GraphQL guide overlay --------------------------------------------
    function wireGuide() {
        const G = window.INTROSPECTRE_GUIDE;
        const btn = byId("guide-btn");
        const overlay = byId("guide-overlay");
        const closeBtn = byId("guide-close");
        if (!G || !btn || !overlay) return;

        // Rebuild on each open so the "detected framework" reflects the current target.
        function build() {
            const fp = ((DATA && DATA.serverFingerprint) || "").toLowerCase();
            let fwKey = null;
            for (const k of Object.keys(G.frameworks)) { if (fp.includes(k)) { fwKey = k; break; } }

            let toc = `<div class="guide-title">GraphQL Security</div>`;
            let body = "";
            if (fwKey) {
                toc += `<a class="guide-toc-item detected" href="#g-detected">Detected: ${escapeHtml(fwKey)}</a>`;
                body += `<section id="g-detected" class="guide-section detected"><h4>Detected framework</h4><p>${G.frameworks[fwKey]}</p></section>`;
            }
            G.sections.forEach((s) => {
                toc += `<a class="guide-toc-item" href="#g-${escapeAttr(s.id)}">${escapeHtml(s.title)}</a>`;
                body += `<section id="g-${escapeAttr(s.id)}" class="guide-section"><h4>${escapeHtml(s.title)}</h4>${s.html}</section>`;
            });
            byId("guide-toc").innerHTML = toc;
            byId("guide-content").innerHTML = body;
            byId("guide-toc").querySelectorAll(".guide-toc-item").forEach((a) =>
                a.addEventListener("click", (ev) => {
                    ev.preventDefault();
                    const el = document.getElementById(a.getAttribute("href").slice(1));
                    if (el) el.scrollIntoView({ behavior: "smooth", block: "start" });
                    byId("guide-toc").querySelectorAll(".guide-toc-item").forEach((x) => x.classList.remove("active"));
                    a.classList.add("active");
                }));
        }

        const open = () => { build(); overlay.classList.add("open"); };
        const close = () => overlay.classList.remove("open");
        btn.addEventListener("click", open);
        closeBtn && closeBtn.addEventListener("click", close);
        overlay.addEventListener("click", (e) => { if (e.target === overlay) close(); });
        document.addEventListener("keydown", (e) => { if (e.key === "Escape") close(); });
    }

    // ---- Helpers -----------------------------------------------------------
    function collectVisibleEdges() {
        return graph.edges().map((id) => masterEdges.find((e) => e._id === id)).filter(Boolean);
    }
    function dedupeEdges(list) {
        const seen = new Set(); const out = [];
        list.forEach((e) => { if (!seen.has(e._id)) { seen.add(e._id); out.push(e); } });
        return out;
    }
    function isNeighbor(a, b) {
        return (outAdj.get(b) || []).some((e) => e.target === a) ||
               (inAdj.get(b) || []).some((e) => e.source === a);
    }
    function isScalarish(id) { const n = nodeById.get(id); return n && SCALARISH.has(n.kind); }
    function updateCounts() {
        byId("node-count").textContent = graph.order + " nodes";
        byId("edge-count").textContent = graph.size + " edges";
    }
    function findingsForType(typeId) {
        return (DATA.findings || []).filter((f) => (f.affected || []).some((a) => typeOf(a) === typeId));
    }
    function typeOf(affected) {
        // Affected strings look like "Type", "Type.field", or "Type.field(arg)".
        return String(affected).split(/[.(]/)[0];
    }
    function fade(hex) {
        if (!hex || hex[0] !== "#") return "#2a3240";
        const n = parseInt(hex.slice(1), 16);
        const r = (n >> 16) & 255, g = (n >> 8) & 255, b = n & 255;
        const mix = (c) => Math.round(c * 0.28 + 20);
        return `rgb(${mix(r)},${mix(g)},${mix(b)})`;
    }
    function section(title, inner) { return `<div class="detail-section"><h4>${escapeHtml(title)}</h4>${inner}</div>`; }
    // `clean` marks a code block as a query template whose `#` comment lines should be dropped
    // on copy (they stay visible on screen). Left off for PoC / exploit-guide / sqlmap blocks.
    function codeBlock(code, clean) { return `<button class="copy-btn"${clean ? ' data-clean="1"' : ''}>copy</button><pre class="code">${escapeHtml(code)}</pre>`; }
    function stripComments(code) {
        return code.split("\n")
            .map((l) => l.replace(/\s+#\s.*$/, ""))       // drop inline " # …" annotations
            .filter((l) => !/^\s*#/.test(l))               // drop whole-line comments
            .join("\n")
            .replace(/\n{3,}/g, "\n\n")                    // collapse blank runs the comments left
            .replace(/^\s*\n+/, "")                         // trim leading blank lines
            .trimEnd();
    }
    function copyText(text, btn) {
        const out = (btn && btn.dataset && btn.dataset.clean) ? stripComments(text) : text;
        navigator.clipboard && navigator.clipboard.writeText(out).then(() => {
            const old = btn.textContent; btn.textContent = "copied!"; setTimeout(() => (btn.textContent = old), 1200);
        });
    }
    function toast(msg) {
        const el = document.getElementById("endpoint-url");
        const old = el.textContent; el.textContent = msg; el.style.color = "var(--med)";
        setTimeout(() => { el.textContent = old; el.style.color = ""; }, 2500);
    }
    function truncate(s, n) { return s.length > n ? s.slice(0, n) + "…" : s; }
    function byId(id) { return document.getElementById(id); }
    function escapeHtml(s) { return String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])); }
    function escapeAttr(s) { return escapeHtml(s); }
})();
