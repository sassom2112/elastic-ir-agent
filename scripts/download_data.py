"""
Download attack data from open-source repositories.

Sources:
  - EVTX-ATTACK-SAMPLES: Windows event logs mapped to MITRE ATT&CK
  - Splunk Attack Data: curated attack scenarios (JSON/CSV)
"""

import os
import subprocess
import sys
from pathlib import Path

RAW_DIR = Path(__file__).parent.parent / "data" / "raw"
RAW_DIR.mkdir(parents=True, exist_ok=True)

SOURCES = {
    "evtx-attack-samples": {
        "type": "git",
        "url": "https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES.git",
        "dest": RAW_DIR / "evtx-attack-samples",
        "description": "Windows EVTX logs mapped to MITRE ATT&CK",
    },
    "splunk-attack-data": {
        "type": "git",
        "url": "https://github.com/splunk/attack_data.git",
        "dest": RAW_DIR / "splunk-attack-data",
        # sparse checkout — full repo is large, we only need specific datasets
        "sparse_paths": [
            "datasets/attack_techniques/T1110",  # brute force
            "datasets/attack_techniques/T1003",  # credential dumping
            "datasets/attack_techniques/T1021",  # lateral movement
        ],
        "description": "Splunk curated attack datasets (subset: T1110, T1003, T1021)",
    },
}


def clone_repo(name: str, source: dict) -> None:
    dest = source["dest"]
    if dest.exists():
        print(f"[{name}] already cloned, skipping")
        return

    print(f"[{name}] cloning {source['url']} ...")

    if source.get("sparse_paths"):
        subprocess.run(
            ["git", "clone", "--filter=blob:none", "--sparse", source["url"], str(dest)],
            check=True,
        )
        subprocess.run(
            ["git", "-C", str(dest), "sparse-checkout", "set"] + source["sparse_paths"],
            check=True,
        )
    else:
        subprocess.run(
            ["git", "clone", "--depth=1", source["url"], str(dest)],
            check=True,
        )

    print(f"[{name}] done -> {dest}")


def main() -> None:
    for name, source in SOURCES.items():
        if source["type"] == "git":
            clone_repo(name, source)

    print("\nAll sources downloaded.")
    print(f"Data location: {RAW_DIR}")


if __name__ == "__main__":
    main()
