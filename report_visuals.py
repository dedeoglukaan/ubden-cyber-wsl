"""UBDEN rapor görsel bileşenleri — siber estetik, infografik, çevrimdışı.

Saf ReportLab vektörüdür; harici grafik kütüphanesi veya binary gerektirmez.
Her bileşen renk ve font adlarını parametre olarak alır, bir Drawing veya Table
döndürür ve uygulama durumundan bağımsızdır (taşınabilir). Renkler UBDEN
kurumsal paletidir (lacivert/teal); rapor motoru bunları PDF ve HTML'de kullanır.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from reportlab.graphics.shapes import Circle, Drawing, Line, Rect, String, Wedge
from reportlab.lib import colors
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, Table, TableStyle

BASE = Path(__file__).resolve().parent

# --- UBDEN kurumsal paleti ---
NAVY = colors.HexColor("#101b32")
TEAL = colors.HexColor("#00b9bd")
TEAL_DEEP = colors.HexColor("#00858a")
INK = colors.HexColor("#263249")
GRAY = colors.HexColor("#65758b")
LINE = colors.HexColor("#dce5eb")
TRACK = colors.HexColor("#e4e9f4")
PALE = colors.HexColor("#edf7f8")
DEEP = colors.HexColor("#0a1526")
GRID = colors.HexColor("#1b2a45")
TEXT_ON_DARK = colors.HexColor("#e6ecf9")
DIM_ON_DARK = colors.HexColor("#90a0c4")

OK = colors.HexColor("#1f9e73")
WARN = colors.HexColor("#e49722")
DANGER = colors.HexColor("#c0304a")

# Önem derecesi renkleri (UBDEN raporunun mevcut HTML/PDF değerleriyle uyumlu).
SEVERITY_COLORS = {
    "critical": colors.HexColor("#9d174d"),
    "high": colors.HexColor("#d84734"),
    "medium": colors.HexColor("#e49722"),
    "low": colors.HexColor("#337ec6"),
    "info": colors.HexColor("#73859c"),
}


def grade_for_score(score: float) -> str:
    """0-100 skorunu A-E notuna çevirir (100 en iyi)."""
    if score >= 90:
        return "A"
    if score >= 75:
        return "B"
    if score >= 60:
        return "C"
    if score >= 40:
        return "D"
    return "E"


def grade_color(grade: str) -> colors.Color:
    return {"A": OK, "B": colors.HexColor("#57b98a"), "C": WARN,
            "D": colors.HexColor("#e06d2e"), "E": DANGER}.get(
        (grade or "").upper(), GRAY)


def score_color(score: float) -> colors.Color:
    if score >= 85:
        return OK
    if score >= 70:
        return colors.HexColor("#57b98a")
    if score >= 50:
        return WARN
    if score >= 30:
        return colors.HexColor("#e06d2e")
    return DANGER


def severity_color(sev: str) -> colors.Color:
    return SEVERITY_COLORS.get((sev or "").lower(), GRAY)


# --------------------------------------------------------------------------
# Font zinciri — Türkçe destekli, indirmesiz, sistem fontlarına düşer
# --------------------------------------------------------------------------

TURKISH_SAMPLE = "ĞÜŞİÖÇğüşıöç"

# (görünen ad, normal dosya, kalın dosya) — tercih sırasına göre.
_FONT_CANDIDATES = [
    ("DejaVu Sans", "DejaVuSans.ttf", "DejaVuSans-Bold.ttf"),
    ("Liberation Sans", "LiberationSans-Regular.ttf", "LiberationSans-Bold.ttf"),
    ("Noto Sans", "NotoSans-Regular.ttf", "NotoSans-Bold.ttf"),
    ("Segoe UI", "segoeui.ttf", "segoeuib.ttf"),
    ("Arial", "arial.ttf", "arialbd.ttf"),
    ("Tahoma", "tahoma.ttf", "tahomabd.ttf"),
]

REGULAR_KEY = "DV"
BOLD_KEY = "DVB"


def _font_search_dirs() -> list[Path]:
    dirs = [BASE / "assets"]
    if os.name == "nt":
        system_root = os.environ.get("SystemRoot", r"C:\Windows")
        dirs.append(Path(system_root) / "Fonts")
        local = os.environ.get("LOCALAPPDATA")
        if local:
            dirs.append(Path(local) / "Microsoft" / "Windows" / "Fonts")
    else:
        dirs += [
            Path("/usr/share/fonts/truetype/dejavu"),
            Path("/usr/share/fonts/truetype/liberation"),
            Path("/usr/share/fonts"),
            Path.home() / ".fonts",
        ]
    return [d for d in dirs if d.is_dir()]


def _find_font(filename: str) -> Path | None:
    for directory in _font_search_dirs():
        candidate = directory / filename
        if candidate.is_file():
            return candidate
    return None


def _supports_turkish(path: Path) -> bool:
    """Fontun Türkçe karakterleri gerçekten içerdiğini glif eşlemesiyle doğrular."""
    try:
        from reportlab.pdfbase import pdfmetrics
        from reportlab.pdfbase.ttfonts import TTFont
    except ImportError:
        return False
    probe_key = f"UB-Probe-{path.stem}"
    try:
        if probe_key not in pdfmetrics.getRegisteredFontNames():
            pdfmetrics.registerFont(TTFont(probe_key, str(path)))
        mapping = pdfmetrics.getFont(probe_key).face.charToGlyph
    except Exception:
        return False
    return all(mapping.get(ord(char), 0) for char in TURKISH_SAMPLE)


def register_fonts() -> tuple[str, str]:
    """Türkçeyi destekleyen ilk uygun fontu 'DV'/'DVB' anahtarlarına kaydeder.

    Rapor motorunun bugünkü sabit 'DV'/'DVB' anahtarlarıyla uyumludur: assets
    içindeki DejaVu bulunursa onu kullanır, yoksa sistem fontuna düşer. Hiçbiri
    olmazsa ('Helvetica','Helvetica-Bold') döner (Türkçe glifleri eksik olabilir).
    """
    from reportlab.lib.fonts import addMapping
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont

    registered = pdfmetrics.getRegisteredFontNames()
    if REGULAR_KEY in registered:
        return REGULAR_KEY, (BOLD_KEY if BOLD_KEY in registered else REGULAR_KEY)

    for _name, regular, bold in _FONT_CANDIDATES:
        regular_path = _find_font(regular)
        if regular_path is None or not _supports_turkish(regular_path):
            continue
        try:
            pdfmetrics.registerFont(TTFont(REGULAR_KEY, str(regular_path)))
        except Exception:
            continue
        bold_path = _find_font(bold)
        bold_key = REGULAR_KEY
        if bold_path is not None and _supports_turkish(bold_path):
            try:
                pdfmetrics.registerFont(TTFont(BOLD_KEY, str(bold_path)))
                bold_key = BOLD_KEY
            except Exception:
                bold_key = REGULAR_KEY
        addMapping(REGULAR_KEY, 0, 0, REGULAR_KEY)
        addMapping(REGULAR_KEY, 1, 0, bold_key)
        return REGULAR_KEY, bold_key
    return "Helvetica", "Helvetica-Bold"


# --------------------------------------------------------------------------
# Halka (donut) gösterge — skoru merkezde büyük, renkli yay ile
# --------------------------------------------------------------------------


def donut_gauge(score: float, grade: str, bold_font: str, base_font: str,
                size: float = 36 * mm, hole_bg: colors.Color = colors.white,
                color: colors.Color | None = None,
                caption: str = "NOT") -> Drawing:
    """0-100 skorunu renkli halka göstergesi olarak çizer (merkezde skor + not)."""
    d = Drawing(size, size)
    cx = cy = size / 2
    radius = size / 2
    inner = radius * 0.66
    frac = max(0.0, min(1.0, float(score) / 100.0))
    col = color or grade_color(grade)

    d.add(Circle(cx, cy, radius, fillColor=TRACK, strokeColor=None))
    if frac > 0:
        d.add(Wedge(cx, cy, radius, 90 - 360 * frac, 90,
                    fillColor=col, strokeColor=None))
    d.add(Circle(cx, cy, inner, fillColor=hole_bg, strokeColor=None))

    num_color = INK if hole_bg == colors.white else TEXT_ON_DARK
    d.add(String(cx, cy + 0.5 * mm, str(int(round(score))),
                 textAnchor="middle", fontName=bold_font,
                 fontSize=size * 0.30, fillColor=num_color))
    d.add(String(cx, cy - size * 0.20, f"{caption} {grade}".strip(),
                 textAnchor="middle", fontName=base_font,
                 fontSize=size * 0.11, fillColor=col))
    return d


# --------------------------------------------------------------------------
# Renkli istatistik kutuları (KPI tiles)
# --------------------------------------------------------------------------


def stat_tiles(items: list[tuple[str, str, colors.Color]], width: float,
               bold_font: str, base_font: str, height: float = 20 * mm) -> Table:
    """Renkli KPI kutuları — büyük değer + etiket. items: (değer, etiket, renk)."""
    if not items:
        return Table([[""]], colWidths=[width])
    n = len(items)
    gap = 3 * mm
    tile_w = (width - gap * (n - 1)) / n

    num_style = ParagraphStyle("tile_num", fontName=bold_font, fontSize=20,
                               leading=23, alignment=1, textColor=colors.white)
    lbl_style = ParagraphStyle("tile_lbl", fontName=base_font, fontSize=7.6,
                               leading=10, alignment=1,
                               textColor=colors.HexColor("#eaf0ff"))

    def tile(value: str, label: str, col: colors.Color) -> Table:
        t = Table([[Paragraph(str(value), num_style)],
                   [Paragraph(str(label), lbl_style)]],
                  colWidths=[tile_w], rowHeights=[height * 0.58, height * 0.42])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), col),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 2),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
            ("LINEBELOW", (0, 0), (-1, 0), 2, colors.Color(1, 1, 1, 0.25)),
        ]))
        return t

    cells: list[Any] = []
    widths: list[float] = []
    for i, (value, label, col) in enumerate(items):
        cells.append(tile(value, label, col))
        widths.append(tile_w)
        if i < n - 1:
            cells.append("")
            widths.append(gap)
    outer = Table([cells], colWidths=widths, hAlign="LEFT")
    outer.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (-1, -1), 0),
        ("TOPPADDING", (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
    ]))
    return outer


# --------------------------------------------------------------------------
# Yatay çubuk grafik (tablo hücrelerinden — grafik kütüphanesi yok)
# --------------------------------------------------------------------------


def hbars(entries: list[tuple[str, int, colors.Color]], width: float,
          label_style: ParagraphStyle, value_style: ParagraphStyle,
          label_w: float = 46 * mm) -> Table:
    """Renkli yatay çubuk grafik. entries: (etiket, değer, renk)."""
    if not entries:
        return Table([[Paragraph("Veri yok", label_style)]], colWidths=[width])
    maximum = max((c for _, c, _ in entries), default=1) or 1
    bar_area = max(6 * mm, width - label_w - 12 * mm)
    rows: list[list[Any]] = []
    cmds: list[Any] = [
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 2.5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2.5),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
    ]
    for i, (label, count, col) in enumerate(entries):
        filled = max(1.2 * mm, bar_area * count / maximum)
        bar = Table([[""]], colWidths=[filled], rowHeights=[4 * mm])
        bar.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), col),
            ("LEFTPADDING", (0, 0), (-1, -1), 0), ("RIGHTPADDING", (0, 0), (-1, -1), 0),
            ("TOPPADDING", (0, 0), (-1, -1), 0), ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
        ]))
        rows.append([Paragraph(str(label), label_style), bar,
                     Paragraph(f"<b>{count}</b>", value_style)])
        cmds.append(("ALIGN", (2, i), (2, i), "RIGHT"))
    t = Table(rows, colWidths=[label_w, bar_area, 12 * mm], hAlign="LEFT")
    t.setStyle(TableStyle(cmds))
    return t


# --------------------------------------------------------------------------
# Bölüm başlığı bandı
# --------------------------------------------------------------------------


def section_band(title: str, width: float, bold_font: str,
                 base_font: str, subtitle: str = "") -> Table:
    """Koyu siber bölüm başlığı bandı — sol accent şeridiyle."""
    title_style = ParagraphStyle("band_title", fontName=bold_font, fontSize=13,
                                 leading=16, textColor=colors.white)
    cells = [[Paragraph(title, title_style)]]
    heights = [8 * mm]
    if subtitle:
        sub_style = ParagraphStyle("band_sub", fontName=base_font, fontSize=8,
                                   leading=10, textColor=DIM_ON_DARK)
        cells.append([Paragraph(subtitle, sub_style)])
        heights.append(5 * mm)
    t = Table(cells, colWidths=[width], rowHeights=heights, hAlign="LEFT")
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), NAVY),
        ("LINEBEFORE", (0, 0), (0, -1), 3, TEAL),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))
    return t


# --------------------------------------------------------------------------
# Siber kapak zemini (ilk sayfa canvas'ına çizilir) — markasız
# --------------------------------------------------------------------------


def cover_backdrop(canvas, width: float, height: float,
                   base_font: str, footer_left: str = "",
                   footer_right: str = "") -> None:
    """İlk sayfaya tam ekran siber kapak zemini çizer (metin story ile üstüne gelir)."""
    canvas.saveState()
    canvas.setFillColor(NAVY)
    canvas.rect(0, 0, width, height, stroke=0, fill=1)
    canvas.setFillColor(DEEP)
    canvas.rect(0, height * 0.62, width, height * 0.38, stroke=0, fill=1)

    # İnce ızgara motifi.
    canvas.setStrokeColor(GRID)
    canvas.setLineWidth(0.4)
    step = 12 * mm
    x = 0.0
    while x <= width:
        canvas.line(x, 0, x, height)
        x += step
    y = 0.0
    while y <= height:
        canvas.line(0, y, width, y)
        y += step

    # Sağ üstte iç içe accent halkaları (radar/hedef hissi).
    canvas.setStrokeColor(TEAL_DEEP)
    canvas.setLineWidth(1.0)
    ccx, ccy = width - 30 * mm, height - 40 * mm
    for r in (10 * mm, 20 * mm, 32 * mm, 46 * mm):
        canvas.circle(ccx, ccy, r, stroke=1, fill=0)
    canvas.setStrokeColor(TEAL)
    canvas.setLineWidth(1.6)
    canvas.circle(ccx, ccy, 20 * mm, stroke=1, fill=0)

    # Kalkan glifi (sol üst).
    sx, sy = 20 * mm, height - 34 * mm
    canvas.setFillColor(TEAL)
    p = canvas.beginPath()
    p.moveTo(sx, sy + 9 * mm)
    p.lineTo(sx + 8 * mm, sy + 5 * mm)
    p.lineTo(sx + 8 * mm, sy - 2 * mm)
    p.curveTo(sx + 8 * mm, sy - 7 * mm, sx + 4 * mm, sy - 9 * mm, sx, sy - 10 * mm)
    p.curveTo(sx - 4 * mm, sy - 9 * mm, sx - 8 * mm, sy - 7 * mm, sx - 8 * mm, sy - 2 * mm)
    p.lineTo(sx - 8 * mm, sy + 5 * mm)
    p.close()
    canvas.drawPath(p, stroke=0, fill=1)
    canvas.setStrokeColor(NAVY)
    canvas.setLineWidth(1.4)
    canvas.line(sx, sy + 4 * mm, sx, sy - 5 * mm)
    canvas.line(sx - 4.5 * mm, sy + 1 * mm, sx + 4.5 * mm, sy + 1 * mm)

    # Alt accent çizgisi + künye.
    canvas.setStrokeColor(TEAL)
    canvas.setLineWidth(2)
    canvas.line(18 * mm, 22 * mm, width - 18 * mm, 22 * mm)
    canvas.setFillColor(DIM_ON_DARK)
    canvas.setFont(base_font, 8)
    if footer_left:
        canvas.drawString(18 * mm, 16 * mm, footer_left)
    if footer_right:
        canvas.drawRightString(width - 18 * mm, 16 * mm, footer_right)
    canvas.restoreState()


# --------------------------------------------------------------------------
# İlişki / saldırı-yüzeyi grafiği (dış ↔ iç, iki kolon)
# --------------------------------------------------------------------------

_LEFT_TYPES = {"company", "domain", "hosting", "email", "breach", "person",
               "lookalike", "extport", "external"}
_RIGHT_TYPES = {"network", "service", "database", "device", "cve", "internal"}


def _node_color(risk: str) -> colors.Color:
    return {"critical": DANGER, "high": WARN, "medium": WARN}.get(
        (risk or "").lower(), TEAL)


def relationship_graph(graph: dict[str, Any], width: float, bold: str, base: str):
    """İlişki ağını iki kolonlu (dış ↔ iç) bir vektör çizim olarak üretir.

    graph = {"nodes":[{id,label,type,risk}], "edges":[{source,target,label}]}
    """
    nodes = graph.get("nodes") or []
    edges = graph.get("edges") or []

    left = [n for n in nodes if n.get("type") in _LEFT_TYPES
            or n.get("type") not in _RIGHT_TYPES][:12]
    right = [n for n in nodes if n.get("type") in _RIGHT_TYPES][:12]

    pad_top = 12 * mm
    row_h = 8.2 * mm
    rows = max(len(left), len(right), 1)
    height = pad_top + rows * row_h + 6 * mm

    d = Drawing(width, height)
    d.add(Rect(0, 0, width, height, fillColor=NAVY, strokeColor=None))

    x_left = 46 * mm
    x_right = width - 46 * mm

    def layout(items: list[dict[str, Any]]) -> dict[str, float]:
        pos: dict[str, float] = {}
        n = len(items)
        for i, node in enumerate(items):
            y = height - pad_top - (i + 0.5) * ((height - pad_top - 4 * mm) / max(n, 1))
            pos[node["id"]] = y
        return pos

    lpos = layout(left)
    rpos = layout(right)
    coords: dict[str, tuple[float, float]] = {}
    for node in left:
        coords[node["id"]] = (x_left, lpos[node["id"]])
    for node in right:
        coords[node["id"]] = (x_right, rpos[node["id"]])

    d.add(String(x_left, height - 5 * mm, "DIŞ SALDIRI YÜZEYİ",
                 textAnchor="middle", fontName=bold, fontSize=7.5, fillColor=TEAL))
    d.add(String(x_right, height - 5 * mm, "İÇ AĞ / ZAFİYET",
                 textAnchor="middle", fontName=bold, fontSize=7.5, fillColor=TEAL))

    for e in edges:
        s = coords.get(e.get("source"))
        t = coords.get(e.get("target"))
        if not s or not t:
            continue
        bridge = abs(s[0] - t[0]) > 1 * mm
        if bridge:
            d.add(Line(s[0], s[1], t[0], t[1], strokeColor=DANGER, strokeWidth=1.3))
            midx, midy = (s[0] + t[0]) / 2, (s[1] + t[1]) / 2
            if e.get("label"):
                d.add(String(midx, midy + 1.2 * mm, str(e["label"])[:22],
                             textAnchor="middle", fontName=base, fontSize=5.4,
                             fillColor=WARN))
        else:
            d.add(Line(s[0], s[1], t[0], t[1], strokeColor=GRID, strokeWidth=0.6))

    def draw_nodes(items: list[dict[str, Any]], x: float, anchor: str,
                   label_dx: float) -> None:
        for node in items:
            _, y = coords[node["id"]]
            col = _node_color(node.get("risk", "info"))
            d.add(Circle(x, y, 1.7 * mm, fillColor=col, strokeColor=DEEP, strokeWidth=0.5))
            d.add(String(x + label_dx, y - 1.0 * mm, str(node.get("label", ""))[:30],
                         textAnchor=anchor, fontName=base, fontSize=6.3,
                         fillColor=TEXT_ON_DARK))

    draw_nodes(left, x_left, "end", -3 * mm)
    draw_nodes(right, x_right, "start", 3 * mm)
    return d
