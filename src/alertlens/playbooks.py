"""Incident-response playbooks as data: every step has an ID the model must cite.

Asking the model to *select step IDs* rather than write recommendations turns grounding into
a set-membership check: an ID outside the retrieved playbook is a hallucination by definition,
and it is dropped before anything reaches an analyst.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

_STEP = re.compile(r"^- \[(?P<id>[A-Z0-9]+-[A-Z]\d+)\] (?P<text>.+)$")
_SECTION = re.compile(r"^## (?P<name>.+)$")


@dataclass
class Playbook:
    id: str
    title: str
    families: list[str]
    techniques: list[str]
    steps: dict[str, str] = field(default_factory=dict)  # step id -> text
    sections: dict[str, list[str]] = field(default_factory=dict)  # section -> step ids

    def render(self) -> str:
        lines = [f"{self.id}: {self.title}"]
        for section, ids in self.sections.items():
            lines.append(f"{section}:")
            lines += [f"  {i}: {self.steps[i]}" for i in ids]
        return "\n".join(lines)


def parse(text: str) -> Playbook:
    _, front, body = text.split("---", 2)
    meta = yaml.safe_load(front)
    pb = Playbook(meta["id"], meta["title"], meta.get("families", []), meta.get("techniques", []))
    section = "Steps"
    for line in body.strip().splitlines():
        if m := _SECTION.match(line):
            section = m.group("name")
        elif m := _STEP.match(line):
            pb.steps[m.group("id")] = m.group("text")
            pb.sections.setdefault(section, []).append(m.group("id"))
    return pb


class Library:
    def __init__(self, playbooks: list[Playbook]) -> None:
        self.playbooks = playbooks
        self._vectorizer = TfidfVectorizer(ngram_range=(1, 2), sublinear_tf=True)
        self._matrix = self._vectorizer.fit_transform(
            [pb.title + " " + " ".join(pb.steps.values()) for pb in playbooks]
        )

    @classmethod
    def load(cls, directory: str | Path) -> Library:
        files = sorted(Path(directory).glob("*.md"))
        return cls([parse(f.read_text(encoding="utf-8")) for f in files])

    def get(self, playbook_id: str) -> Playbook:
        return next(pb for pb in self.playbooks if pb.id == playbook_id)

    def retrieve(self, family: str, techniques: list[str], query: str = "") -> Playbook:
        """Route on metadata first (exact, explainable), fall back to lexical similarity."""
        for pb in self.playbooks:
            if family in pb.families:
                return pb
        for pb in self.playbooks:
            if set(techniques) & set(pb.techniques):
                return pb
        scores = cosine_similarity(self._vectorizer.transform([f"{family} {query}"]), self._matrix)
        return self.playbooks[int(scores.argmax())]
