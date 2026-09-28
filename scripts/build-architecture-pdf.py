#!/usr/bin/env python3
"""Build the two-page ULPF architecture evaluation document."""

from pathlib import Path
import sys

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    Flowable,
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)


NAVY = colors.HexColor("#0B1F33")
BLUE = colors.HexColor("#176B87")
CYAN = colors.HexColor("#64CCC5")
PALE = colors.HexColor("#EAF6F6")
INK = colors.HexColor("#1B2633")
MUTED = colors.HexColor("#526271")
LINE = colors.HexColor("#CCD8E2")


class ArchitectureFlow(Flowable):
    def __init__(self, width):
        super().__init__()
        self.width = width
        self.height = 86

    def draw(self):
        labels = [
            "Listeners\nHTTP / Syslog",
            "Durable\nadmission",
            "Leased\nworker",
            "Immutable\nenvelope",
            "Query and\nconnectors",
        ]
        gap = 12
        box_width = (self.width - gap * 4) / 5
        for index, label in enumerate(labels):
            x = index * (box_width + gap)
            self.canv.setFillColor(PALE if index % 2 == 0 else colors.white)
            self.canv.setStrokeColor(BLUE)
            self.canv.roundRect(x, 18, box_width, 52, 7, fill=1, stroke=1)
            self.canv.setFillColor(NAVY)
            self.canv.setFont("Helvetica-Bold", 8.2)
            lines = label.split("\n")
            for offset, line in enumerate(lines):
                self.canv.drawCentredString(x + box_width / 2, 48 - offset * 11, line)
            if index < len(labels) - 1:
                start = x + box_width + 2
                end = x + box_width + gap - 2
                self.canv.setStrokeColor(CYAN)
                self.canv.setLineWidth(2)
                self.canv.line(start, 44, end, 44)
                self.canv.line(end - 4, 48, end, 44)
                self.canv.line(end - 4, 40, end, 44)
        self.canv.setFillColor(MUTED)
        self.canv.setFont("Helvetica", 7.3)
        self.canv.drawString(0, 3, "Exact bytes and occurrence identity remain available through every stage and every replay.")


def styles():
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle(
            "Title", parent=base["Title"], fontName="Helvetica-Bold", fontSize=20,
            leading=23, textColor=NAVY, alignment=TA_LEFT, spaceAfter=5,
        ),
        "subtitle": ParagraphStyle(
            "Subtitle", parent=base["BodyText"], fontName="Helvetica", fontSize=9.4,
            leading=12, textColor=MUTED, spaceAfter=9,
        ),
        "h1": ParagraphStyle(
            "H1", parent=base["Heading1"], fontName="Helvetica-Bold", fontSize=11.5,
            leading=14, textColor=BLUE, spaceBefore=6, spaceAfter=4,
        ),
        "body": ParagraphStyle(
            "Body", parent=base["BodyText"], fontName="Helvetica", fontSize=8.1,
            leading=10.4, textColor=INK, spaceAfter=4,
        ),
        "small": ParagraphStyle(
            "Small", parent=base["BodyText"], fontName="Helvetica", fontSize=7.35,
            leading=9.1, textColor=INK,
        ),
        "table_head": ParagraphStyle(
            "TableHead", parent=base["BodyText"], fontName="Helvetica-Bold", fontSize=7.2,
            leading=8.5, textColor=colors.white,
        ),
        "table": ParagraphStyle(
            "Table", parent=base["BodyText"], fontName="Helvetica", fontSize=6.9,
            leading=8.4, textColor=INK,
        ),
    }


def bullet(text, style):
    return Paragraph("<font color='#176B87'>&#8226;</font>&nbsp; " + text, style)


def footer(canvas, doc):
    canvas.saveState()
    canvas.setStrokeColor(LINE)
    canvas.line(doc.leftMargin, 26, letter[0] - doc.rightMargin, 26)
    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(MUTED)
    canvas.drawString(doc.leftMargin, 15, "Universal Log Pre-processing Framework | Architecture")
    canvas.drawRightString(letter[0] - doc.rightMargin, 15, f"Page {doc.page}")
    canvas.restoreState()


def build(output):
    style = styles()
    doc = SimpleDocTemplate(
        str(output), pagesize=letter, leftMargin=0.48 * inch, rightMargin=0.48 * inch,
        topMargin=0.38 * inch, bottomMargin=0.42 * inch,
        title="Universal Log Pre-processing Framework Architecture",
        author="Siddhant Parashar",
        subject="Two-page implementation architecture",
    )
    width = letter[0] - doc.leftMargin - doc.rightMargin
    story = [
        Paragraph("Universal Log Pre-processing Framework", style["title"]),
        Paragraph(
            "Implementation architecture for lossless, deterministic, extensible perimeter-device event processing",
            style["subtitle"],
        ),
        ArchitectureFlow(width),
        Paragraph("Scope and definition of universal", style["h1"]),
        Paragraph(
            "ULPF uses one durable transport, detection, envelope, provenance, query, and extension contract across supported sources. "
            "Syntax and semantics still require tested built-in parsers or declarative source bundles. It does not claim automatic semantic understanding of arbitrary proprietary data.",
            style["body"],
        ),
    ]

    flow_rows = [[Paragraph("Stage", style["table_head"]), Paragraph("Durable behavior and output", style["table_head"])]]
    stages = [
        ("1. Frame and admit", "HTTP, UDP Syslog, and TCP Syslog enforce framing and byte limits. Exact application bytes are fsynced before an ACCEPTED receipt is committed in SQLite WAL."),
        ("2. Detect and interpret", "A leased worker verifies size and SHA-256, scores deterministic candidates, parses within byte/field/depth/token/time limits, and applies declarative mappings."),
        ("3. Validate and preserve", "An immutable revision stores status, issues, versions, canonical fields, parsed/unmapped material, unmatched bytes, provenance, and deterministic quality."),
        ("4. Deliver and query", "Connector-specific durable state drives ClickHouse, NDJSON, and authenticated HTTP delivery. Scoped APIs expose search, history, and separately authorized raw bytes."),
    ]
    for stage, behavior in stages:
        flow_rows.append([Paragraph(stage, style["table"]), Paragraph(behavior, style["table"])])
    table = Table(flow_rows, colWidths=[1.18 * inch, width - 1.18 * inch], repeatRows=1)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), NAVY),
        ("GRID", (0, 0), (-1, -1), 0.35, LINE),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, PALE]),
    ]))
    story.extend([
        table,
        Paragraph("Lossless event envelope", style["h1"]),
        Paragraph(
            "Every revision links receipt and revision identity, acquisition metadata, framing, raw reference and SHA-256, parser/mapping/schema versions, interpretation status, typed issues, preserved parsed content, canonical event fields, field-level provenance, and quality. Reprocessing creates a new revision over the same immutable evidence.",
            style["body"],
        ),
        KeepTogether([
            Paragraph("Failure semantics", style["h1"]),
            bullet("Unknown, ambiguous, invalid, and failed events remain visible and replayable.", style["small"]),
            bullet("Expired processing and delivery leases recover after restart without changing occurrence identity.", style["small"]),
            bullet("A sink failure delays that sink only; partial success never marks another connector successful.", style["small"]),
        ]),
        PageBreak(),
        Paragraph("Security reliability and production evolution", style["title"]),
        Paragraph(
            "The prototype is a Go modular monolith for one offline-capable host. Its contracts preserve a direct path to distributed evidence, streaming, control, and analytics services when measurements justify the operational cost.",
            style["subtitle"],
        ),
    ])

    invariant_rows = [[Paragraph("Invariant", style["table_head"]), Paragraph("Enforcement", style["table_head"])]]
    invariants = [
        ("No acknowledged loss", "HTTP success occurs only after exact evidence and receipt state are durable. Raw hash and byte length are rechecked before interpretation."),
        ("Bounded untrusted input", "Listeners, detectors, parsers, schemas, issue text, queries, responses, retries, and worker concurrency have explicit limits."),
        ("Traceable semantics", "Each canonical leaf requires provenance and one mapping identity. Unsupported meaning stays parsed or unmapped instead of being guessed."),
        ("Least privilege", "Tokens separate events:write, events:read, raw:read, replay:write, config scopes, and ops:read, with tenant restrictions."),
        ("Safe operations", "Errors and audit data exclude raw bytes and secrets. The container is non-root, read-only-root compatible, capability-free, and uses mounted secrets."),
    ]
    for invariant, enforcement in invariants:
        invariant_rows.append([Paragraph(invariant, style["table"]), Paragraph(enforcement, style["table"])])
    invariant_table = Table(invariant_rows, colWidths=[1.34 * inch, width - 1.34 * inch], repeatRows=1)
    invariant_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), NAVY),
        ("GRID", (0, 0), (-1, -1), 0.35, LINE),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, PALE]),
    ]))
    story.extend([
        invariant_table,
        Spacer(1, 4),
        Paragraph("Plug-in onboarding and controlled replay", style["h1"]),
        Paragraph(
            "Immutable bundles carry fingerprints, an anchored RE2 parser, mappings, taxonomies, schema extensions, and fixtures. Installation validates safe paths and digest identity. Source-profile activation uses a compare-and-swap revision; rollback selects a prior digest. Replay is a separate authorized action and retains every prior revision.",
            style["body"],
        ),
    ])

    evolution = [
        [Paragraph("Concern", style["table_head"]), Paragraph("Evaluation host", style["table_head"]), Paragraph("Production path", style["table_head"])],
        [Paragraph("Raw evidence", style["table"]), Paragraph("fsynced local files", style["table"]), Paragraph("versioned object storage", style["table"])],
        [Paragraph("Work queue", style["table"]), Paragraph("SQLite WAL and leases", style["table"]), Paragraph("partitioned stream and control DB", style["table"])],
        [Paragraph("Analytics", style["table"]), Paragraph("single-node ClickHouse", style["table"]), Paragraph("replicated or sharded ClickHouse", style["table"])],
        [Paragraph("Deployment", style["table"]), Paragraph("hardened Compose stack", style["table"]), Paragraph("orchestrated services using the same contracts", style["table"])],
    ]
    evolution_table = Table(evolution, colWidths=[1.15 * inch, 2.2 * inch, width - 3.35 * inch], repeatRows=1)
    evolution_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), BLUE),
        ("GRID", (0, 0), (-1, -1), 0.35, LINE),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, PALE]),
    ]))
    story.extend([
        evolution_table,
        Paragraph("Deployment and evaluation evidence", style["h1"]),
        bullet("Compose uses pinned images, named volumes, health checks, local secret mounts, dropped capabilities, and a read-only root filesystem.", style["small"]),
        bullet("The offline archive includes image tar files, configuration, licenses, version metadata, and SHA-256 verification before loading.", style["small"]),
        bullet("Tests cover schemas, parser ground truth, fuzzing, race detection, restart recovery, authorization, connector outage/replay, container policy, and fault injection.", style["small"]),
        bullet("Benchmark reports bind results to hardware plus code, config, bundle, image, and workload digests. No unmeasured throughput claim is made.", style["small"]),
        Spacer(1, 5),
        Paragraph(
            "Decision boundary: the prototype demonstrates end-to-end correctness and operability on one host; billion-event-per-day scale is a contract-preserving production target that requires measured partitioning and replicated infrastructure.",
            ParagraphStyle("Decision", parent=style["body"], backColor=PALE, borderColor=CYAN, borderWidth=0.8, borderPadding=7, textColor=NAVY),
        ),
    ])
    doc.build(story, onFirstPage=footer, onLaterPages=footer)


def main():
    root = Path(__file__).resolve().parents[1]
    output = Path(sys.argv[1]) if len(sys.argv) > 1 else root / "output" / "pdf" / "ULPF-Architecture-Two-Pager.pdf"
    output.parent.mkdir(parents=True, exist_ok=True)
    build(output)
    print(output)


if __name__ == "__main__":
    main()
