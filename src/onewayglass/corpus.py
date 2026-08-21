"""Synthetic organisation with a realistic permission hierarchy.

WHY SYNTHETIC

A leak demonstration needs documents whose sensitivity is unambiguous. Real documents
would mean either sourcing confidential material — which is not acceptable — or using
public documents and pretending they are secret, which produces a demo nobody believes.

This org is small enough to reason about by hand and structured enough that the
count-inference attack is genuinely available: some departments have many documents and
some have few, which is exactly what makes result counts informative to an attacker.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum


class Level(IntEnum):
    """Seniority. Higher sees more, within their own department."""

    IC = 1
    LEAD = 2
    DIRECTOR = 3
    EXEC = 4


@dataclass(frozen=True, slots=True)
class Principal:
    """Who is asking."""

    id: str
    name: str
    department: str
    level: Level
    #: Explicit grants beyond department+level, e.g. a legal reviewer on one matter.
    extra_docs: frozenset[str] = frozenset()


@dataclass(frozen=True, slots=True)
class Document:
    id: str
    title: str
    department: str
    #: Minimum level required within the owning department.
    min_level: Level
    text: str
    #: True when any employee may read it regardless of department.
    company_wide: bool = False

    def readable_by(self, p: Principal) -> bool:
        """The authoritative access rule. Everything else must agree with this.

        EXEC is cross-department by design. The first version of this model gave the CEO
        only `exec` documents, which made a CEO see fewer documents than an engineer —
        caught by a control in the leak harness that compared readable counts against
        seniority. An access model where seniority does not monotonically widen access is
        not a realistic hierarchy, and would have made every subsequent measurement
        meaningless.
        """
        if self.id in p.extra_docs:
            return True
        if self.company_wide:
            return True
        if p.level >= Level.EXEC:
            return True
        if self.department != p.department:
            return False
        return p.level >= self.min_level


PRINCIPALS: tuple[Principal, ...] = (
    Principal("u_ic_eng", "Engineer", "engineering", Level.IC),
    Principal("u_lead_eng", "Eng Lead", "engineering", Level.LEAD),
    Principal("u_dir_eng", "Eng Director", "engineering", Level.DIRECTOR),
    Principal("u_ic_sales", "Account Exec", "sales", Level.IC),
    Principal("u_dir_sales", "Sales Director", "sales", Level.DIRECTOR),
    Principal("u_ic_people", "People Partner", "people", Level.IC),
    Principal("u_dir_people", "People Director", "people", Level.DIRECTOR),
    Principal("u_exec", "CEO", "exec", Level.EXEC),
    # A contractor with one explicit grant and nothing else. Tests that an extra grant
    # widens access by exactly one document and no more.
    Principal("u_contractor", "Contractor", "external", Level.IC, frozenset({"doc_eng_04"})),
)

PRINCIPALS_BY_ID = {p.id: p for p in PRINCIPALS}


def _doc(
    n: str,
    title: str,
    dept: str,
    level: Level,
    text: str,
    company_wide: bool = False,
) -> Document:
    return Document(n, title, dept, level, text, company_wide)


#: Deliberately uneven per-department counts. `people` holds few but highly sensitive
#: documents while `engineering` holds many mundane ones — so a result count alone is
#: informative, which is the whole premise of the count-inference attack.
DOCUMENTS: tuple[Document, ...] = (
    # ── company-wide (9) ────────────────────────────────────────────────────
    _doc(
        "doc_all_01",
        "Code of Conduct",
        "exec",
        Level.IC,
        "All employees are expected to act with integrity and report concerns without fear of retaliation.",
        True,
    ),
    _doc(
        "doc_all_02",
        "Expense Policy",
        "exec",
        Level.IC,
        "Travel expenses require pre-approval above five hundred pounds. Receipts must be submitted within thirty days.",
        True,
    ),
    _doc(
        "doc_all_03",
        "Security Basics",
        "engineering",
        Level.IC,
        "Enable multi-factor authentication on every account. Never share credentials over chat or email.",
        True,
    ),
    _doc(
        "doc_all_04",
        "Remote Work Policy",
        "people",
        Level.IC,
        "Employees may work remotely up to three days per week with manager agreement.",
        True,
    ),
    _doc(
        "doc_all_05",
        "Holiday Allowance",
        "people",
        Level.IC,
        "Twenty-eight days of annual leave plus public holidays. Unused days do not carry over.",
        True,
    ),
    _doc(
        "doc_all_06",
        "Incident Reporting",
        "engineering",
        Level.IC,
        "Page the on-call engineer for any customer-facing outage. Write a blameless postmortem within five working days.",
        True,
    ),
    _doc(
        "doc_all_07",
        "Brand Guidelines",
        "sales",
        Level.IC,
        "Use the primary logo on light backgrounds. Never stretch or recolour the mark.",
        True,
    ),
    _doc(
        "doc_all_08",
        "Onboarding Checklist",
        "people",
        Level.IC,
        "New joiners complete security training, tooling setup and a first-week buddy session.",
        True,
    ),
    _doc(
        "doc_all_09",
        "Data Retention",
        "exec",
        Level.IC,
        "Customer data is retained for seven years then deleted. Backups follow the same schedule.",
        True,
    ),
    # ── engineering: many, mostly mundane (11) ──────────────────────────────
    _doc(
        "doc_eng_01",
        "Service Architecture",
        "engineering",
        Level.IC,
        "The platform runs eleven services behind an API gateway with Redis for caching and Postgres for durable state.",
    ),
    _doc(
        "doc_eng_02",
        "Deployment Runbook",
        "engineering",
        Level.IC,
        "Deployments run through the pipeline on merge to main. Roll back by re-deploying the previous tagged image.",
    ),
    _doc(
        "doc_eng_03",
        "On-call Rotation",
        "engineering",
        Level.IC,
        "One primary and one secondary per week. Handover happens Monday morning with a written summary.",
    ),
    _doc(
        "doc_eng_04",
        "Vendor Integration Spec",
        "engineering",
        Level.IC,
        "The payment vendor requires mutual TLS and a signed webhook secret rotated every ninety days.",
    ),
    _doc(
        "doc_eng_05",
        "Load Test Results",
        "engineering",
        Level.LEAD,
        "The service saturates at four thousand requests per second with p99 latency of two hundred milliseconds.",
    ),
    _doc(
        "doc_eng_06",
        "Technical Debt Register",
        "engineering",
        Level.LEAD,
        "The legacy billing module has no test coverage and blocks three planned features.",
    ),
    _doc(
        "doc_eng_07",
        "Hiring Scorecards",
        "engineering",
        Level.LEAD,
        "Candidates are assessed on system design, code quality and collaboration with a written rubric.",
    ),
    _doc(
        "doc_eng_08",
        "Security Audit Findings",
        "engineering",
        Level.DIRECTOR,
        "The external audit found two high-severity issues in session handling and one in credential storage.",
    ),
    _doc(
        "doc_eng_09",
        "Infrastructure Cost Breakdown",
        "engineering",
        Level.DIRECTOR,
        "Compute accounts for sixty percent of spend, with the data warehouse a further twenty-five percent.",
    ),
    _doc(
        "doc_eng_10",
        "Platform Rewrite Proposal",
        "engineering",
        Level.DIRECTOR,
        "A phased rewrite of the ingestion layer would take two quarters and require three additional engineers.",
    ),
    _doc(
        "doc_eng_11",
        "Outage Postmortem Q3",
        "engineering",
        Level.LEAD,
        "A misconfigured connection pool exhausted database connections during peak traffic for forty minutes.",
    ),
    # ── sales (6) ───────────────────────────────────────────────────────────
    _doc(
        "doc_sales_01",
        "Pipeline Review",
        "sales",
        Level.IC,
        "Twelve opportunities are in late stage with a combined value of one point four million.",
    ),
    _doc(
        "doc_sales_02",
        "Objection Handling",
        "sales",
        Level.IC,
        "When price is raised, move the conversation to total cost of ownership and integration effort.",
    ),
    _doc(
        "doc_sales_03",
        "Territory Assignments",
        "sales",
        Level.LEAD,
        "Northern Europe is split between two representatives with accounts allocated by employee count.",
    ),
    _doc(
        "doc_sales_04",
        "Discount Approval Matrix",
        "sales",
        Level.LEAD,
        "Discounts up to fifteen percent are rep-approved. Above thirty percent requires director sign-off.",
    ),
    _doc(
        "doc_sales_05",
        "Lost Deal Analysis",
        "sales",
        Level.DIRECTOR,
        "Of eleven losses last quarter, seven cited missing compliance certification as the deciding factor.",
    ),
    _doc(
        "doc_sales_06",
        "Commission Structure",
        "sales",
        Level.DIRECTOR,
        "Accelerators begin at one hundred percent of quota and double the rate above one hundred and twenty.",
    ),
    # ── people: few but highly sensitive (5) ────────────────────────────────
    _doc(
        "doc_people_01",
        "Interview Process",
        "people",
        Level.IC,
        "Four stages: screen, technical, system design and values. Feedback is written within one working day.",
    ),
    _doc(
        "doc_people_02",
        "Performance Calibration",
        "people",
        Level.LEAD,
        "Ratings are moderated across teams to correct for manager leniency before being finalised.",
    ),
    _doc(
        "doc_people_03",
        "Compensation Bands",
        "people",
        Level.DIRECTOR,
        "Senior engineering bands run from ninety to one hundred and thirty thousand with a fifteen percent target bonus.",
    ),
    _doc(
        "doc_people_04",
        "Grievance Case Notes",
        "people",
        Level.DIRECTOR,
        "Three formal grievances were raised this year. Two were resolved informally and one is ongoing.",
    ),
    _doc(
        "doc_people_05",
        "Redundancy Planning",
        "people",
        Level.DIRECTOR,
        "A reduction of eleven roles across two departments is under consideration for the next fiscal year.",
    ),
    # ── exec: the most sensitive (4) ────────────────────────────────────────
    _doc(
        "doc_exec_01",
        "Board Minutes",
        "exec",
        Level.EXEC,
        "The board approved the funding round and requested a revised hiring plan before the next meeting.",
    ),
    _doc(
        "doc_exec_02",
        "Acquisition Discussions",
        "exec",
        Level.EXEC,
        "Preliminary conversations with two potential acquirers are ongoing under mutual non-disclosure.",
    ),
    _doc(
        "doc_exec_03",
        "Runway Analysis",
        "exec",
        Level.EXEC,
        "Current burn gives nineteen months of runway, reducing to fourteen with the planned hiring.",
    ),
    _doc(
        "doc_exec_04",
        "Executive Succession",
        "exec",
        Level.EXEC,
        "Succession candidates have been identified for three of five executive positions.",
    ),
)

DOCUMENTS_BY_ID = {d.id: d for d in DOCUMENTS}


def visible_to(p: Principal) -> list[Document]:
    """Ground truth: exactly what this principal may read."""
    return [d for d in DOCUMENTS if d.readable_by(p)]


def access_summary() -> dict[str, int]:
    """Document count per principal. Useful for showing how uneven access is."""
    return {p.id: len(visible_to(p)) for p in PRINCIPALS}
