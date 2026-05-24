"""Generate all docs/images from Python — no LaTeX required."""
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
    yo = 0.18 if sub else 0
    ax.text(cx, cy + yo, label, ha="center", va="center",
            color=lc, fontsize=fs, fontweight="bold" if bold else "normal",
            fontfamily="monospace", zorder=3)
    if sub:
        ax.text(cx, cy - 0.22, sub, ha="center", va="center",
                color=MUTED, fontsize=sub_fs, fontfamily="monospace", zorder=3)


def arr(ax, x1, y1, x2, y2, color=MUTED):
    ax.annotate("", xy=(x2, y2), xytext=(x1, y1), zorder=3,
                arrowprops=dict(arrowstyle="-|>", color=color,
                                lw=1.8, mutation_scale=14))


# ══════════════════════════════════════════════════════════════════════════════
# 1. Architecture
# ══════════════════════════════════════════════════════════════════════════════
fig, ax = plt.subplots(figsize=(14, 11))
fig.patch.set_facecolor(BG)
ax.set_facecolor(BG)
ax.set_xlim(0, 14); ax.set_ylim(0, 11)
ax.axis("off")

# Title
ax.text(7, 10.6, "Elastic IR Agent — Architecture",
        ha="center", va="center", color=TEXT,
        fontsize=16, fontweight="bold", fontfamily="monospace")

# ── Alert/Prompt ──
rbox(ax, 7, 10.0, 3.2, 0.6, ACCENT, "Alert / Prompt",
     label_color=ACCENT, fs=12, bold=True)
arr(ax, 7, 9.70, 7, 9.15)

# ── Triage Agent container ──
ax.add_patch(FancyBboxPatch((0.4, 7.0), 13.2, 2.0,
    boxstyle="round,pad=0.02", facecolor="#0a1a2a",
    edgecolor=GREEN, linewidth=2.5, zorder=1))
ax.text(7, 8.82, "Triage Agent  (Gemini 2.5 Flash via Conversational Agents)",
        ha="center", va="center", color=GREEN,
        fontsize=12, fontweight="bold", fontfamily="monospace")

# Tool columns inside triage
left_tools  = ["· unique_hosts_by_technique", "· credential_access_events",
               "· suspicious_process_execution"]
right_tools = ["· lateral_movement_detection", "· attack_timeline",
               "· failed_logins_by_host"]
mem_tools   = ["· search_memory", "· write_memory"]

ax.text(2.2, 8.55, "Elastic MCP tools:", color=MUTED, fontsize=9,
        fontfamily="monospace", ha="left")
ax.text(6.8, 8.55, "Elastic MCP tools (cont.):", color=MUTED, fontsize=9,
        fontfamily="monospace", ha="left")
ax.text(11.6, 8.55, "Memory:", color=MUTED, fontsize=9,
        fontfamily="monospace", ha="left")

for i, t in enumerate(left_tools):
    ax.text(2.2, 8.28 - i*0.36, t, color=ACCENT, fontsize=10,
            fontfamily="monospace", ha="left")
for i, t in enumerate(right_tools):
    ax.text(6.8, 8.28 - i*0.36, t, color=ACCENT, fontsize=10,
            fontfamily="monospace", ha="left")
for i, t in enumerate(mem_tools):
    ax.text(11.6, 8.28 - i*0.36, t, color=ORANGE, fontsize=10,
            fontfamily="monospace", ha="left")

# vertical dividers
for xv in [6.5, 11.3]:
    ax.plot([xv, xv], [7.1, 8.7], color=BORDER, lw=1, ls="--", zorder=2)

# ── Arrows down from triage ──
arr(ax, 4.0, 7.0, 3.2, 6.25)   # → Cloud Run proxy
arr(ax, 10.0, 7.0, 10.8, 6.25) # → ES Memory
arr(ax, 7.0, 7.0, 7.0, 6.55)   # → IR Report label

# ── Cloud Run Proxy ──
rbox(ax, 3.2, 5.85, 4.8, 0.7, ACCENT,
     "Cloud Run MCP Proxy",
     label_color=ACCENT, fs=12, bold=True,
     sub="REST → JSON-RPC 2.0  |  auth injection  |  public endpoint",
     sub_fs=9)

# ── Elasticsearch Memory ──
rbox(ax, 10.8, 5.85, 4.2, 0.7, ORANGE,
     "Elasticsearch Memory",
     label_color=ORANGE, fs=12, bold=True,
     sub="ELSER + BM25 hybrid  |  ir-agent-memory index",
     sub_fs=9)

# ── Elastic Cloud Serverless ──
rbox(ax, 3.2, 4.65, 4.8, 0.7, GREEN,
     "Elastic Cloud Serverless",
     label_color=GREEN, fs=12, bold=True,
     sub="73,909 Windows attack events  |  6 custom ES|QL tools",
     sub_fs=9)
arr(ax, 3.2, 5.5, 3.2, 5.0)

# ── IR Report box ──
rbox(ax, 7.0, 6.1, 4.0, 0.6, TEXT,
     "IR Report  (Attack Chain + MITRE + IOCs)",
     fs=11)
arr(ax, 7.0, 5.8, 7.0, 5.25)

# ── Forensic Auditor container ──
ax.add_patch(FancyBboxPatch((1.0, 3.9), 12.0, 1.1,
    boxstyle="round,pad=0.02", facecolor="#1a0d20",
    edgecolor=ORANGE, linewidth=2.5, zorder=1))
ax.text(7, 5.22, "Forensic Auditor  (second independent Gemini pass — read-only tools)",
        ha="center", va="center", color=ORANGE,
        fontsize=12, fontweight="bold", fontfamily="monospace")
ax.text(7, 4.72,
        "VERIFIED  ·  REFUTED  ·  UNVERIFIABLE   —   every claim cited against raw ES|QL evidence",
        ha="center", va="center", color=MUTED,
        fontsize=10, fontfamily="monospace")
arr(ax, 7.0, 3.9, 7.0, 3.35)

# ── Output files ──
rbox(ax, 7.0, 3.05, 9.0, 0.55, MUTED,
     "reports/ir_report_<session>.md     reports/verification_<session>.md     audit_log.jsonl",
     label_color=MUTED, fs=9.5)

# ── Legend ──
items = [("● Elastic MCP tools", ACCENT), ("● Memory tools", ORANGE),
         ("● Triage boundary", GREEN), ("● Auditor boundary", ORANGE)]
for i, (lbl, col) in enumerate(items):
    ax.text(0.5 + i*3.4, 0.35, lbl, color=col, fontsize=9,
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

# header line
ax.plot([0.02, 0.98], [1.0 - 0.85/fig_h]*2,
        transform=ax.transAxes, color=BORDER, lw=1.2)

col1_x = 0.03   # control label
col2_x = 0.26   # implementation text
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
    # row top in axes coords
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

# footer
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
# 3. IR Report demo — placeholder banner
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
