"""Generate docs/images from Python — no LaTeX required."""
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch
from pathlib import Path

OUT = Path(__file__).parent / "images"
OUT.mkdir(exist_ok=True)

BG     = "#0d1117"
SURF   = "#161b22"
BORDER = "#30363d"
TEXT   = "#e6edf3"
MUTED  = "#8b949e"
ACCENT = "#58a6ff"
GREEN  = "#3fb950"
ORANGE = "#db6d28"
PURPLE = "#bc8cff"
RED    = "#f85149"
YELLOW = "#d29922"


def rbox(ax, cx, cy, w, h, edge, label, label_color=None,
         fs=11, bold=False, sub=None, sub_fs=9, face=None):
    face = face or SURF
    ax.add_patch(FancyBboxPatch(
        (cx - w/2, cy - h/2), w, h,
        boxstyle="round,pad=0.015",
        facecolor=face, edgecolor=edge, linewidth=2,
        zorder=2,
    ))
    lc = label_color or TEXT
    yo = 0.22 if sub else 0
    ax.text(cx, cy + yo, label, ha="center", va="center",
            color=lc, fontsize=fs, fontweight="bold" if bold else "normal",
            fontfamily="monospace", zorder=3)
    if sub:
        ax.text(cx, cy - 0.26, sub, ha="center", va="center",
                color=MUTED, fontsize=sub_fs, fontfamily="monospace", zorder=3)


def arr(ax, x1, y1, x2, y2, color=MUTED):
    ax.annotate("", xy=(x2, y2), xytext=(x1, y1), zorder=3,
                arrowprops=dict(arrowstyle="-|>", color=color,
                                lw=1.8, mutation_scale=14))


# ══════════════════════════════════════════════════════════════════════════════
# 1. Architecture  — figure 14 × 15, ylim 0–15, plenty of vertical room
# ══════════════════════════════════════════════════════════════════════════════
W, H = 14, 15
fig, ax = plt.subplots(figsize=(W, H))
fig.patch.set_facecolor(BG)
ax.set_facecolor(BG)
ax.set_xlim(0, W); ax.set_ylim(0, H)
ax.axis("off")

# ── Title
ax.text(7, 14.55, "Elastic IR Agent — Architecture",
        ha="center", va="center", color=TEXT,
        fontsize=16, fontweight="bold", fontfamily="monospace")

# ── Alert / Prompt  (y-center = 13.75)
rbox(ax, 7, 13.75, 3.4, 0.65, ACCENT, "Alert / Prompt",
     label_color=ACCENT, fs=12, bold=True)
arr(ax, 7, 13.42, 7, 12.85)

# ── Triage Agent container  (y = 10.5 → 12.7, height = 2.2)
ax.add_patch(FancyBboxPatch((0.4, 10.5), 13.2, 2.2,
    boxstyle="round,pad=0.02", facecolor="#0a1a2a",
    edgecolor=GREEN, linewidth=2.5, zorder=1))
ax.text(7, 12.45, "Triage Agent  (Gemini 2.5 Flash via Conversational Agents)",
        ha="center", va="center", color=GREEN,
        fontsize=12, fontweight="bold", fontfamily="monospace")

# Tool columns
left_tools  = ["· unique_hosts_by_technique",
               "· credential_access_events",
               "· suspicious_process_execution"]
right_tools = ["· lateral_movement_detection",
               "· attack_timeline",
               "· failed_logins_by_host"]
mem_tools   = ["· search_memory", "· write_memory"]

for col_x, header, tools, col in [
    (2.2,  "Elastic MCP tools:",         left_tools,  ACCENT),
    (6.8,  "Elastic MCP tools (cont.):", right_tools, ACCENT),
    (11.6, "Memory:",                    mem_tools,   ORANGE),
]:
    ax.text(col_x, 12.12, header, color=MUTED, fontsize=9,
            fontfamily="monospace", ha="left")
    for i, t in enumerate(tools):
        ax.text(col_x, 11.82 - i * 0.38, t, color=col, fontsize=10,
                fontfamily="monospace", ha="left")

for xv in [6.5, 11.3]:
    ax.plot([xv, xv], [10.65, 12.1], color=BORDER, lw=1, ls="--", zorder=2)

# ── Three arrows down from triage bottom (y = 10.5)
arr(ax, 3.5,  10.5, 3.2,  9.7)   # → Cloud Run
arr(ax, 7.0,  10.5, 7.0,  9.7)   # → IR Report
arr(ax, 10.5, 10.5, 10.8, 9.7)   # → ES Memory

# ── Cloud Run MCP Proxy  (cy = 9.2)
rbox(ax, 3.2, 9.2, 4.9, 0.8, ACCENT,
     "Cloud Run MCP Proxy",
     label_color=ACCENT, fs=11, bold=True,
     sub="REST → JSON-RPC 2.0  |  auth injection  |  public endpoint",
     sub_fs=9)

# ── IR Report  (cy = 9.2)
rbox(ax, 7.0, 9.2, 4.2, 0.8, TEXT,
     "IR Report",
     label_color=TEXT, fs=11, bold=True,
     sub="Attack Chain  ·  MITRE ATT&CK  ·  IOCs",
     sub_fs=9)

# ── Elasticsearch Memory  (cy = 9.2)
rbox(ax, 10.8, 9.2, 4.0, 0.8, ORANGE,
     "Elasticsearch Memory",
     label_color=ORANGE, fs=11, bold=True,
     sub="ELSER + BM25  |  ir-agent-memory",
     sub_fs=9)

# ── Arrow Cloud Run → Elastic Cloud
arr(ax, 3.2, 8.8, 3.2, 8.05)

# ── Elastic Cloud Serverless  (cy = 7.65)
rbox(ax, 3.2, 7.65, 4.9, 0.8, GREEN,
     "Elastic Cloud Serverless",
     label_color=GREEN, fs=11, bold=True,
     sub="73,909 Windows attack events  |  6 custom ES|QL tools",
     sub_fs=9)

# ── Arrow IR Report → Forensic Auditor
arr(ax, 7.0, 8.8, 7.0, 7.3)

# ── Forensic Auditor container  (y = 5.7 → 7.2, height = 1.5)
ax.add_patch(FancyBboxPatch((1.0, 5.7), 12.0, 1.5,
    boxstyle="round,pad=0.02", facecolor="#1a0d20",
    edgecolor=ORANGE, linewidth=2.5, zorder=1))
ax.text(7, 6.95, "Forensic Auditor  (second independent Gemini pass — read-only tools)",
        ha="center", va="center", color=ORANGE,
        fontsize=12, fontweight="bold", fontfamily="monospace")
ax.text(7, 6.35,
        "VERIFIED  ·  REFUTED  ·  UNVERIFIABLE   —   every claim cited against raw ES|QL evidence",
        ha="center", va="center", color=MUTED,
        fontsize=10, fontfamily="monospace")

# ── Arrow Forensic Auditor → Output
arr(ax, 7.0, 5.7, 7.0, 5.05)

# ── Output files  (cy = 4.7)
rbox(ax, 7.0, 4.7, 10.5, 0.65, BORDER,
     "reports/ir_report_<session>.md   ·   reports/verification_<session>.md   ·   audit_log.jsonl",
     label_color=MUTED, fs=9.5)

# ── Legend
items = [("● Elastic MCP tools", ACCENT), ("● Memory tools", ORANGE),
         ("● Triage boundary", GREEN),     ("● Auditor boundary", ORANGE)]
for i, (lbl, col) in enumerate(items):
    ax.text(0.6 + i * 3.4, 0.45, lbl, color=col, fontsize=9,
            fontfamily="monospace")

plt.tight_layout(pad=0.4)
plt.savefig(OUT / "architecture.png", dpi=150, bbox_inches="tight",
            facecolor=BG, edgecolor="none")
plt.close()
print("architecture.png done")


# ══════════════════════════════════════════════════════════════════════════════
# 2. Security Model
# ══════════════════════════════════════════════════════════════════════════════
controls = [
    ("Session isolation",
     "search_memory is scoped to session_id at the Elasticsearch filter.\n"
     "Model cannot query across investigations — physically blocked,\n"
     "not instructed away."),
    ("Input validation",
     "Every tool argument validated before any ES call.\n"
     "time_window: regex + 100-year DoS cap.  host_name: alphanumeric\n"
     "allowlist + ES|QL char blocklist.  Integers range-checked."),
    ("Write allowlist",
     "write_memory checks target index against hardcoded allowlist\n"
     "(ir-agent-memory). Misconfiguring ELASTIC_INDEX_MEMORY=ir-events\n"
     "is blocked at write time — not at config time."),
    ("Content sanitization",
     "write_memory strips control characters, caps input at 10,000 chars.\n"
     "Blocks indirect prompt injection via poisoned retrieval results."),
    ("Split API keys",
     "ELASTIC_API_KEY_READ for ES|QL queries.\n"
     "ELASTIC_API_KEY_WRITE for memory index only.\n"
     "Separate scoped keys — read path cannot write."),
    ("Structural labeling",
     "Tool results wrapped with _provenance metadata.\n"
     "Model treats retrieved data as data — not instructions.\n"
     "Structural boundary enforced by schema, not regex."),
    ("Chain-of-custody log",
     "Every tool call atomically appended to audit_log.jsonl\n"
     "via os.open/os.write (not buffered IO).\n"
     "Blocked calls log rejection reason; allowed calls log duration."),
]

n = len(controls)
row_h = 0.9
fig_h = n * row_h + 2.0

fig, ax = plt.subplots(figsize=(14, fig_h))
fig.patch.set_facecolor(BG)
ax.set_facecolor(BG)
ax.axis("off")

ax.text(0.5, 1.0 - 0.3/fig_h,
        "Security Model — Structural Controls",
        transform=ax.transAxes, ha="center", va="top",
        color=TEXT, fontsize=15, fontweight="bold", fontfamily="monospace")

ax.plot([0.02, 0.98], [1.0 - 0.85/fig_h]*2,
        transform=ax.transAxes, color=BORDER, lw=1.2)

col1_x = 0.03
col2_x = 0.26
header_y = 1.0 - 1.0/fig_h

ax.text(col1_x, header_y, "Control", transform=ax.transAxes,
        ha="left", va="top", color=MUTED, fontsize=11,
        fontfamily="monospace", fontweight="bold")
ax.text(col2_x, header_y, "Implementation", transform=ax.transAxes,
        ha="left", va="top", color=MUTED, fontsize=11,
        fontfamily="monospace", fontweight="bold")

ax.plot([0.02, 0.98], [1.0 - 1.35/fig_h]*2,
        transform=ax.transAxes, color=BORDER, lw=1)

for r, (ctrl, impl) in enumerate(controls):
    row_top = 1.0 - (1.5 + r * row_h) / fig_h
    row_bot = row_top - (row_h - 0.1) / fig_h
    bg = "#0e1520" if r % 2 == 0 else "#12181f"
    ax.add_patch(plt.Rectangle(
        (0.02, row_bot), 0.96, (row_h - 0.08) / fig_h,
        transform=ax.transAxes, facecolor=bg,
        edgecolor="none", clip_on=False, zorder=0))
    mid_y = (row_top + row_bot) / 2 + 0.005
    ax.text(col1_x + 0.005, mid_y, ctrl,
            transform=ax.transAxes, ha="left", va="center",
            color=ACCENT, fontsize=11, fontweight="bold",
            fontfamily="monospace")
    ax.text(col2_x + 0.005, mid_y, impl,
            transform=ax.transAxes, ha="left", va="center",
            color=TEXT, fontsize=10, fontfamily="monospace",
            linespacing=1.55)

ax.plot([0.02, 0.98], [0.03]*2,
        transform=ax.transAxes, color=BORDER, lw=1)
ax.text(0.5, 0.015, "Bad actions are architecturally impossible — not instructed away.",
        transform=ax.transAxes, ha="center", va="bottom",
        color=MUTED, fontsize=10, fontfamily="monospace", style="italic")

plt.tight_layout(pad=0.3)
plt.savefig(OUT / "security_model.png", dpi=150, bbox_inches="tight",
            facecolor=BG, edgecolor="none")
plt.close()
print("security_model.png done")


# ══════════════════════════════════════════════════════════════════════════════
# 3. IR Report demo placeholder
# ══════════════════════════════════════════════════════════════════════════════
fig, ax = plt.subplots(figsize=(14, 3))
fig.patch.set_facecolor(SURF)
ax.set_facecolor(SURF)
ax.axis("off")
ax.add_patch(FancyBboxPatch((0.05, 0.12), 0.9, 0.76,
    boxstyle="round,pad=0.01", facecolor="#0a0f16",
    edgecolor=ACCENT, linewidth=2, transform=ax.transAxes, clip_on=False))
ax.text(0.5, 0.65,
        "Demo Output — Real Screenshot Coming",
        transform=ax.transAxes, ha="center", va="center",
        color=ACCENT, fontsize=16, fontweight="bold", fontfamily="monospace")
ax.text(0.5, 0.35,
        "Run  python agent/local_agent.py --demo  and replace this file with your screenshot",
        transform=ax.transAxes, ha="center", va="center",
        color=MUTED, fontsize=11, fontfamily="monospace")
plt.savefig(OUT / "ir_report_demo.png", dpi=150, bbox_inches="tight",
            facecolor=SURF, edgecolor="none")
plt.close()
print("ir_report_demo.png placeholder done")

print("\nAll images written to", OUT)
