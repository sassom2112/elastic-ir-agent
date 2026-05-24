"""Generate all docs/images from Python — no LaTeX required."""
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch
import numpy as np
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


# ── helpers ──────────────────────────────────────────────────────────────────

def rounded_box(ax, x, y, w, h, color, text, text_color=TEXT,
                font_size=9, bold=False, subtext=None):
    box = FancyBboxPatch(
        (x - w/2, y - h/2), w, h,
        boxstyle="round,pad=0.02",
        facecolor=SURF, edgecolor=color, linewidth=1.5,
    )
    ax.add_patch(box)
    weight = "bold" if bold else "normal"
    ax.text(x, y + (0.03 if subtext else 0), text,
            ha="center", va="center", color=text_color,
            fontsize=font_size, fontweight=weight, fontfamily="monospace")
    if subtext:
        ax.text(x, y - 0.065, subtext,
                ha="center", va="center", color=MUTED,
                fontsize=7, fontfamily="monospace")


def arrow(ax, x1, y1, x2, y2, color=MUTED):
    ax.annotate("", xy=(x2, y2), xytext=(x1, y1),
                arrowprops=dict(arrowstyle="-|>", color=color,
                                lw=1.4, mutation_scale=12))


# ── 1. Architecture diagram ───────────────────────────────────────────────────

fig, ax = plt.subplots(figsize=(11, 8.5))
fig.patch.set_facecolor(BG)
ax.set_facecolor(BG)
ax.set_xlim(0, 10); ax.set_ylim(0, 9)
ax.axis("off")

# title
ax.text(5, 8.6, "Elastic IR Agent — Architecture",
        ha="center", va="center", color=TEXT, fontsize=13,
        fontweight="bold", fontfamily="monospace")

# ── Alert/prompt ──
rounded_box(ax, 5, 7.9, 2.2, 0.45, ACCENT, "Alert / Prompt", text_color=ACCENT, font_size=9, bold=True)
arrow(ax, 5, 7.67, 5, 7.12)

# ── Triage Agent box ──
triage = FancyBboxPatch((1.0, 5.0), 8.0, 1.95,
    boxstyle="round,pad=0.04", facecolor="#0e1f30", edgecolor=GREEN, linewidth=2)
ax.add_patch(triage)
ax.text(5, 6.78, "Triage Agent  (Gemini 2.5 Flash via Conversational Agents)",
        ha="center", va="center", color=GREEN, fontsize=9.5,
        fontweight="bold", fontfamily="monospace")

# tools columns inside triage
tools_left = [
    "unique_hosts_by_technique",
    "credential_access_events",
    "suspicious_process_execution",
]
tools_right = [
    "lateral_movement_detection",
    "attack_timeline",
    "failed_logins_by_host",
]
mem_tools = ["search_memory", "write_memory"]

for i, t in enumerate(tools_left):
    ax.text(2.7, 6.45 - i*0.28, f"· {t}", ha="left", va="center",
            color=ACCENT, fontsize=7.5, fontfamily="monospace")
for i, t in enumerate(tools_right):
    ax.text(5.4, 6.45 - i*0.28, f"· {t}", ha="left", va="center",
            color=ACCENT, fontsize=7.5, fontfamily="monospace")
for i, t in enumerate(mem_tools):
    ax.text(8.1, 6.37 - i*0.28, f"· {t}", ha="left", va="center",
            color=ORANGE, fontsize=7.5, fontfamily="monospace")

ax.text(2.7, 6.60, "Elastic MCP tools:", ha="left", va="center",
        color=MUTED, fontsize=7, fontfamily="monospace")
ax.text(8.1, 6.60, "Memory:", ha="left", va="center",
        color=MUTED, fontsize=7, fontfamily="monospace")
ax.axvline(x=7.95, ymin=(5.0-0)/9, ymax=(6.95-0)/9,
           color=BORDER, linewidth=0.8, linestyle="--")

# ── Cloud Run proxy ──
rounded_box(ax, 2.8, 4.3, 3.2, 0.5, ACCENT,
            "Cloud Run MCP Proxy", text_color=ACCENT, font_size=9, bold=True,
            subtext="REST → JSON-RPC 2.0  |  auth injection")

# ── Elasticsearch memory ──
rounded_box(ax, 7.2, 4.3, 2.8, 0.5, ORANGE,
            "Elasticsearch Memory", text_color=ORANGE, font_size=9, bold=True,
            subtext="ELSER + BM25 hybrid  |  ir-agent-memory")

arrow(ax, 3.5, 5.0, 2.8, 4.57)
arrow(ax, 6.5, 5.0, 7.2, 4.57)

# ── Elastic Cloud ──
rounded_box(ax, 2.8, 3.3, 3.2, 0.5, GREEN,
            "Elastic Cloud Serverless", text_color=GREEN, font_size=9, bold=True,
            subtext="73,909 Windows attack events  |  6 ES|QL tools")
arrow(ax, 2.8, 4.05, 2.8, 3.57)

# ── IR Report ──
arrow(ax, 5, 5.0, 5, 4.45)
rounded_box(ax, 5, 4.2, 2.8, 0.45, TEXT,
            "IR Report  (Attack Chain + MITRE + IOCs)", font_size=8.5)
arrow(ax, 5, 3.97, 5, 3.42)

# ── Forensic Auditor ──
auditor = FancyBboxPatch((1.5, 2.2), 7.0, 1.05,
    boxstyle="round,pad=0.04", facecolor="#1f1420", edgecolor=ORANGE, linewidth=2)
ax.add_patch(auditor)
ax.text(5, 3.05, "Forensic Auditor  (second independent Gemini pass — read-only tools)",
        ha="center", va="center", color=ORANGE, fontsize=8.5,
        fontweight="bold", fontfamily="monospace")
ax.text(5, 2.62, "VERIFIED  ·  REFUTED  ·  UNVERIFIABLE   —  every claim cited against raw ES|QL evidence",
        ha="center", va="center", color=MUTED, fontsize=7.5, fontfamily="monospace")

arrow(ax, 5, 2.2, 5, 1.65)

# ── Output files ──
rounded_box(ax, 5, 1.38, 5.5, 0.45, MUTED,
            "reports/ir_report_<session>.md   reports/verification_<session>.md   audit_log.jsonl",
            text_color=MUTED, font_size=7.5)

# legend
ax.text(0.15, 0.25, "● Elastic MCP tools", color=ACCENT, fontsize=7, fontfamily="monospace")
ax.text(2.2,  0.25, "● Memory tools", color=ORANGE, fontsize=7, fontfamily="monospace")
ax.text(3.9,  0.25, "● Triage Agent boundary", color=GREEN, fontsize=7, fontfamily="monospace")
ax.text(6.2,  0.25, "● Forensic Auditor boundary", color=ORANGE, fontsize=7, fontfamily="monospace")

plt.tight_layout(pad=0.3)
plt.savefig(OUT / "architecture.png", dpi=180, bbox_inches="tight",
            facecolor=BG, edgecolor="none")
plt.close()
print("architecture.png done")


# ── 2. Security model table ───────────────────────────────────────────────────

controls = [
    ("Session isolation",       "search_memory scoped to session_id at the ES filter layer.\nModel cannot query across investigations — physically blocked,\nnot instructed away."),
    ("Input validation",        "Every tool arg validated before any ES call.\ntime_window: regex + 100y DoS cap. host_name: alphanumeric\nallowlist + ES|QL char blocklist. Integers range-checked."),
    ("Write allowlist",         "write_memory checks target index against hardcoded allowlist\n(ir-agent-memory). Misconfigured ELASTIC_INDEX_MEMORY=ir-events\nis blocked at write time — not at config time."),
    ("Content sanitization",    "write_memory strips control characters, caps input at 10,000\nchars before touching Elasticsearch. Blocks indirect prompt\ninjection via poisoned retrieval results."),
    ("Split API keys",          "ELASTIC_API_KEY_READ (ES|QL queries) and\nELASTIC_API_KEY_WRITE (memory index only).\nSeparate scoped keys — read path cannot write."),
    ("Structural labeling",     "Tool results wrapped with _provenance metadata (_context field).\nModel treats retrieved data as data — not as instructions.\nNo regex; structural boundary is enforced by schema."),
    ("Chain-of-custody log",    "Every tool call atomically appended to audit_log.jsonl\nvia os.open/os.write (not buffered IO). Blocked calls log\nrejection reason; allowed calls log duration + args."),
]

fig, ax = plt.subplots(figsize=(12, 8))
fig.patch.set_facecolor(BG)
ax.set_facecolor(BG)
ax.axis("off")

ax.text(0.5, 0.97, "Security Model — Structural Controls",
        transform=ax.transAxes, ha="center", va="top",
        color=TEXT, fontsize=13, fontweight="bold", fontfamily="monospace")

col_x   = [0.01, 0.24]
col_w   = [0.22, 0.75]
row_h   = 1.0 / (len(controls) + 1)
header_y = 0.91

# header
for i, (label, width) in enumerate(zip(["Control", "Implementation"], col_w)):
    ax.text(col_x[i], header_y, label, transform=ax.transAxes,
            ha="left", va="top", color=MUTED, fontsize=8,
            fontfamily="monospace", fontweight="bold")

ax.plot([0.01, 0.99], [header_y - 0.018, header_y - 0.018],
        transform=ax.transAxes, color=BORDER, linewidth=1)

for r, (ctrl, impl) in enumerate(controls):
    y = header_y - 0.022 - r * (0.82 / len(controls))
    bg_color = "#0f1923" if r % 2 == 0 else SURF
    rect = plt.Rectangle((0.005, y - 0.093), 0.99, 0.095,
                          transform=ax.transAxes, facecolor=bg_color,
                          edgecolor="none", clip_on=False)
    ax.add_patch(rect)
    ax.text(col_x[0], y - 0.005, ctrl, transform=ax.transAxes,
            ha="left", va="top", color=ACCENT, fontsize=7.8,
            fontfamily="monospace", fontweight="bold")
    ax.text(col_x[1], y - 0.005, impl, transform=ax.transAxes,
            ha="left", va="top", color=TEXT, fontsize=7.5,
            fontfamily="monospace", linespacing=1.4)

ax.plot([0.01, 0.99], [0.04, 0.04],
        transform=ax.transAxes, color=BORDER, linewidth=0.8)
ax.text(0.5, 0.015, "Bad actions are architecturally impossible — not instructed away.",
        transform=ax.transAxes, ha="center", va="bottom",
        color=MUTED, fontsize=8, fontfamily="monospace", style="italic")

plt.tight_layout(pad=0.2)
plt.savefig(OUT / "security_model.png", dpi=180, bbox_inches="tight",
            facecolor=BG, edgecolor="none")
plt.close()
print("security_model.png done")


# ── 3. IR Report demo output ──────────────────────────────────────────────────

chain = [
    ("1", "2019-07-19", "MSEDGEWIN10", "IEUser",          "T1543.003", "Windows Service",      "AtomicService.exe created via AtomicRedTeam"),
    ("2", "2019-07-19", "MSEDGEWIN10", "IEUser",          "T1490",     "Inhibit Sys Recovery", "vssadmin.exe + wbadmin.exe — shadow copy deletion"),
    ("3", "2019-07-19", "MSEDGEWIN10", "IEUser",          "T1564.001", "Hidden Files",         "bcdedit.exe — boot config tampered"),
    ("4", "2019-07-19", "MSEDGEWIN10", "IEUser",          "T1197",     "BITS Jobs",            "bitsadmin.exe — persistence via BITS"),
    ("5", "2021-04-22", "MSEDGEWIN10", "IEUser",          "T1003.001", "LSASS Memory",         "PPLdump.exe -v lsass lsass.dmp"),
    ("6", "2021-08-07", "MSEDGEWIN10", "IEUser",          "T1566.001", "Spearphishing",        "WINWORD.EXE → stats.doc"),
    ("7", "2021-08-07", "MSEDGEWIN10", "IEUser",          "T1218.007", "Mshta",                "mshta.exe → memViewData.hta"),
    ("8", "2021-08-07", "MSEDGEWIN10", "IEUser",          "T1218.011", "Rundll32",             "rundll32.exe loading memViewData.jpg,PluginInit"),
    ("9", "2021-08-07", "MSEDGEWIN10", "IEUser",          "T1059.003", "Windows CMD",          "cmd.exe runs KDECO.bat, deletes windir env key"),
    ("10","2021-12-07", "MSEDGEWIN10", "IEUser",          "T1003.001", "LSASS Memory",         "MalSeclogon.exe -p 636 -d 2 → lsass.exe accessed"),
]

mitre = [
    ("T1003.001", "Credential Access",    "HIGH",   "314 events, 6 hosts — PPLdump.exe, MalSeclogon.exe, samir.exe"),
    ("T1566.001", "Initial Access",       "HIGH",   "WINWORD.EXE opening stats.doc on MSEDGEWIN10"),
    ("T1218.011", "Defense Evasion",      "HIGH",   "rundll32.exe loading .jpg as DLL via mshta parent"),
    ("T1490",     "Impact",               "HIGH",   "vssadmin.exe + wbadmin.exe — shadow copy deletion"),
    ("T1055",     "Privilege Escalation", "MEDIUM", "208 events across 3 hosts — process injection"),
    ("T1543.003", "Persistence",          "HIGH",   "AtomicService.exe registered as Windows service"),
    ("T1197",     "C2 / Persistence",     "MEDIUM", "bitsadmin.exe — BITS job abuse on MSEDGEWIN10"),
    ("T1068",     "Privilege Escalation", "HIGH",   "SpoolFool.exe (DESKTOP-TTEQ6PR), EfsPotato.exe (LAPTOP-JU4M3I0E)"),
]

fig = plt.figure(figsize=(14, 12))
fig.patch.set_facecolor(BG)

# ── header bar ──
header_ax = fig.add_axes([0, 0.93, 1, 0.07])
header_ax.set_facecolor("#0a0f16")
header_ax.axis("off")
header_ax.text(0.5, 0.68, "Elastic IR Agent — Incident Report",
               transform=header_ax.transAxes, ha="center", va="center",
               color=TEXT, fontsize=14, fontweight="bold", fontfamily="monospace")
header_ax.text(0.5, 0.20,
               "Severity: CRITICAL   |   Status: ACTIVE   |   Timeframe: 2019-07-18 → 2021-12-07   |   Hosts: 6",
               transform=header_ax.transAxes, ha="center", va="center",
               color=RED, fontsize=9, fontfamily="monospace")

# ── attack chain section ──
chain_ax = fig.add_axes([0.01, 0.48, 0.98, 0.43])
chain_ax.set_facecolor(SURF)
chain_ax.axis("off")
chain_ax.text(0.012, 0.97, "Attack Chain",
              transform=chain_ax.transAxes, ha="left", va="top",
              color=GREEN, fontsize=10, fontweight="bold", fontfamily="monospace")

headers = ["#", "Date", "Host", "User", "Technique ID", "Technique", "Evidence"]
col_xs  = [0.012, 0.045, 0.115, 0.225, 0.315, 0.41, 0.535]
header_y = 0.88
for hx, h in zip(col_xs, headers):
    chain_ax.text(hx, header_y, h, transform=chain_ax.transAxes,
                  ha="left", va="top", color=MUTED, fontsize=7.5,
                  fontfamily="monospace", fontweight="bold")
chain_ax.plot([0.01, 0.99], [0.845, 0.845],
              transform=chain_ax.transAxes, color=BORDER, linewidth=0.8)

row_h_pct = 0.075
for r, (step, date, host, user, tid, tech, evidence) in enumerate(chain):
    y = 0.82 - r * row_h_pct
    bg = "#0e1520" if r % 2 == 0 else SURF
    rect = plt.Rectangle((0.005, y - 0.065), 0.99, 0.068,
                          transform=chain_ax.transAxes,
                          facecolor=bg, edgecolor="none", clip_on=False)
    chain_ax.add_patch(rect)
    vals   = [step, date, host, user, tid, tech, evidence]
    colors = [GREEN, MUTED, ACCENT, ORANGE, PURPLE, TEXT, MUTED]
    sizes  = [7.5, 7.5, 7.5, 7.5, 7.5, 7.5, 7.5]
    for cx, val, col, sz in zip(col_xs, vals, colors, sizes):
        chain_ax.text(cx, y - 0.006, val, transform=chain_ax.transAxes,
                      ha="left", va="top", color=col, fontsize=sz,
                      fontfamily="monospace")

# ── MITRE section ──
mitre_ax = fig.add_axes([0.01, 0.01, 0.98, 0.45])
mitre_ax.set_facecolor(SURF)
mitre_ax.axis("off")
mitre_ax.text(0.012, 0.97, "MITRE ATT&CK Mapping",
              transform=mitre_ax.transAxes, ha="left", va="top",
              color=ORANGE, fontsize=10, fontweight="bold", fontfamily="monospace")

mheaders = ["Technique ID", "Tactic", "Confidence", "Evidence"]
mcol_xs  = [0.012, 0.13, 0.30, 0.40]
mitre_ax.plot([0.01, 0.99], [0.88, 0.88],
              transform=mitre_ax.transAxes, color=BORDER, linewidth=0.8)
for mx, mh in zip(mcol_xs, mheaders):
    mitre_ax.text(mx, 0.91, mh, transform=mitre_ax.transAxes,
                  ha="left", va="top", color=MUTED, fontsize=7.5,
                  fontfamily="monospace", fontweight="bold")

conf_colors = {"HIGH": RED, "MEDIUM": YELLOW, "LOW": MUTED}
mrow_h = 0.085
for r, (tid, tactic, conf, evidence) in enumerate(mitre):
    y = 0.855 - r * mrow_h
    bg = "#0e1520" if r % 2 == 0 else SURF
    rect = plt.Rectangle((0.005, y - 0.075), 0.99, 0.078,
                          transform=mitre_ax.transAxes,
                          facecolor=bg, edgecolor="none", clip_on=False)
    mitre_ax.add_patch(rect)
    mitre_ax.text(mcol_xs[0], y - 0.005, tid, transform=mitre_ax.transAxes,
                  ha="left", va="top", color=PURPLE, fontsize=8, fontfamily="monospace", fontweight="bold")
    mitre_ax.text(mcol_xs[1], y - 0.005, tactic, transform=mitre_ax.transAxes,
                  ha="left", va="top", color=TEXT, fontsize=7.5, fontfamily="monospace")
    mitre_ax.text(mcol_xs[2], y - 0.005, conf, transform=mitre_ax.transAxes,
                  ha="left", va="top", color=conf_colors.get(conf, MUTED),
                  fontsize=7.5, fontfamily="monospace", fontweight="bold")
    mitre_ax.text(mcol_xs[3], y - 0.005, evidence, transform=mitre_ax.transAxes,
                  ha="left", va="top", color=MUTED, fontsize=7.5, fontfamily="monospace")

# ── Forensic Auditor verdict bar ──
verdict_ax = fig.add_axes([0.01, 0.0, 0.98, 0.025])
verdict_ax.set_facecolor("#0a0f16")
verdict_ax.axis("off")
verdict_ax.text(0.18, 0.5, "Forensic Auditor:", transform=verdict_ax.transAxes,
                ha="center", va="center", color=MUTED, fontsize=8, fontfamily="monospace")
verdict_ax.text(0.38, 0.5, "Verified: 8", transform=verdict_ax.transAxes,
                ha="center", va="center", color=GREEN, fontsize=8.5,
                fontfamily="monospace", fontweight="bold")
verdict_ax.text(0.53, 0.5, "Refuted: 8", transform=verdict_ax.transAxes,
                ha="center", va="center", color=RED, fontsize=8.5,
                fontfamily="monospace", fontweight="bold")
verdict_ax.text(0.70, 0.5, "Unverifiable: 2", transform=verdict_ax.transAxes,
                ha="center", va="center", color=YELLOW, fontsize=8.5,
                fontfamily="monospace", fontweight="bold")

plt.savefig(OUT / "ir_report_demo.png", dpi=180, bbox_inches="tight",
            facecolor=BG, edgecolor="none")
plt.close()
print("ir_report_demo.png done")

print("\nAll images written to", OUT)
