"""Evaluation figure (matplotlib, Agg), same visual spec as the rest of the portfolio."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import matplotlib

matplotlib.use("Agg")

import matplotlib.pyplot as plt
import numpy as np
from matplotlib.patches import Patch
from matplotlib.ticker import PercentFormatter

SURFACE, INK, INK2, MUTED, GRID = "#fcfcfb", "#0b0b0b", "#52514e", "#898781", "#e1e0d9"
SERIES = ["#2a78d6", "#eb6834", "#1baf7a"]

plt.rcParams.update(
    {
        "font.family": ["Helvetica Neue", "Helvetica", "Arial", "DejaVu Sans"],
        "font.size": 10,
        "axes.labelcolor": INK2,
        "text.color": INK,
        "xtick.color": MUTED,
        "ytick.color": MUTED,
        "xtick.labelcolor": INK2,
        "ytick.labelcolor": INK2,
        "legend.frameon": False,
        "figure.facecolor": SURFACE,
        "axes.facecolor": SURFACE,
        "savefig.facecolor": SURFACE,
    }
)


def comparison(configs: dict[str, Any], path: Path) -> Path:
    labels = {"rules": "Rules only", "llm": "LLM decides", "hybrid": "Hybrid"}
    metrics = [
        ("escalation_recall", "Attack incidents escalated"),
        ("fp_closure_rate", "Benign incidents closed"),
    ]
    fig, ax = plt.subplots(figsize=(7.2, 4.0), dpi=100)
    for spine in ax.spines.values():
        spine.set_visible(False)
    ax.tick_params(length=0)
    ax.grid(axis="y", color=GRID, linewidth=0.8)
    ax.set_axisbelow(True)
    width = 0.24
    for k, key in enumerate(labels):
        vals = [configs[key][m] or 0 for m, _ in metrics]
        xs = np.arange(len(metrics)) + (k - 1) * (width + 0.03)
        ax.bar(xs, vals, width, color=SERIES[k], linewidth=0)
        for x, v in zip(xs, vals, strict=True):
            ax.text(x, v + 0.02, f"{v:.0%}", ha="center", va="bottom", fontsize=9, color=INK2)
    ax.set_xticks(np.arange(len(metrics)), [label for _, label in metrics])
    ax.set_ylim(0, 1.12)
    ax.set_yticks(np.linspace(0, 1, 6))
    ax.yaxis.set_major_formatter(PercentFormatter(1.0))
    ax.legend(
        handles=[Patch(color=SERIES[k], label=v) for k, v in enumerate(labels.values())],
        loc="upper center",
        bbox_to_anchor=(0.5, -0.1),
        ncol=3,
        fontsize=9,
        labelcolor=INK2,
    )
    ax.set_title(
        "Who should decide: rules or the LLM?",
        loc="left",
        fontsize=13,
        fontweight="bold",
        color=INK,
        pad=28,
    )
    ax.text(
        0,
        1.035,
        "Stratified sample of correlated incidents, ground truth from CICIDS2017",
        transform=ax.transAxes,
        fontsize=9.5,
        color=INK2,
        va="bottom",
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(path, dpi=200, bbox_inches="tight", pad_inches=0.25)
    plt.close(fig)
    return path
