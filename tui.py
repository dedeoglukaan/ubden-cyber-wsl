"""Small, dependency-free terminal interface for the UBDEN wizard."""
from __future__ import annotations

import os
import re
import shutil
import sys
import textwrap
import time


class Console:
    COLORS = {
        "navy": "\033[38;5;75m",
        "cyan": "\033[38;5;45m",
        "green": "\033[38;5;84m",
        "yellow": "\033[38;5;221m",
        "red": "\033[38;5;203m",
        "dim": "\033[38;5;250m",
        "bold": "\033[1m",
        "reset": "\033[0m",
    }

    def __init__(self, no_color=False, no_animation=False, stream=None):
        self.stream = stream or sys.stdout
        self.tty = bool(getattr(self.stream, "isatty", lambda: False)())
        self.color = self.tty and not no_color and "NO_COLOR" not in os.environ and os.environ.get("TERM") != "dumb"
        self.animation = self.tty and not no_animation and os.environ.get("TERM") != "dumb"
        self.width = min(max(shutil.get_terminal_size((88, 24)).columns, 48), 108)
        self._last_update = 0.0
        self._last_log = 0.0
        self.completed_targets = 0

    @staticmethod
    def scan_progress(output):
        """Extract Nmap's own phase percentage, without inventing completion."""
        matches = re.findall(r'About\s+(\d+(?:\.\d+)?)%\s+done', output[-16384:], re.I)
        # --stats-every also writes taskprogress to Nmap's XML output; some
        # terminal launches do not flush human-readable timing to stdout.
        matches += re.findall(r'<taskprogress\b[^>]*\bpercent=["\'](\d+(?:\.\d+)?)["\']',output[-16384:],re.I)
        return min(100.0, max(0.0, float(matches[-1]))) if matches else None

    def paint(self, value, color):
        return f"{self.COLORS[color]}{value}{self.COLORS['reset']}" if self.color else value

    def say(self, value="", color=None):
        print(self.paint(value, color) if color else value, file=self.stream, flush=True)

    def banner(self, version):
        # ASCII art remains legible in minimal Kali terminals and SSH sessions.
        art = (
            " _   _ ____  ____  _____ _   _",
            "| | | | __ )|  _ \\| ____| \\ | |",
            "| | | |  _ \\| | | |  _| |  \\| |",
            "| |_| | |_) | |_| | |___| |\\  |",
            " \\___/|____/|____/|_____|_| \\_|",
        )
        self.say()
        for line in art:
            self.say("  " + line, "cyan")
        self.say("  CYBER SECURITY SYSTEMS" + " " * 3 + "v" + version, "bold")
        self.say("  " + "=" * min(self.width - 4, 62), "navy")
        self.say("  Ürün: UBDEN®  |  Tester: görev açılırken girilir", "dim")
        self.say("  Yetkili, kayıtlı ve sınırlı güvenlik değerlendirmesi", "dim")
        self.say()

    def section(self, number, total, title, subtitle=""):
        self.say()
        self.say(f"  [{number:02d}/{total:02d}] {title.upper()}", "cyan")
        self.say("  " + "-" * min(self.width - 4, 62), "navy")
        if subtitle:
            self.say("  " + subtitle, "dim")

    def prompt(self, label, default=""):
        suffix = f" [{default}]" if default else ""
        return input(self.paint(f"  > {label}{suffix}: ", "cyan")).strip() or default

    def menu(self, title, items, default="1"):
        if self.tty and sys.stdin.isatty():
            initial = next((i for i, (key, _) in enumerate(items) if key == default), 0)
            selected = self._navigate(title, [label for _, label in items], initial)
            return items[selected][0]
        self.say("  " + title, "bold")
        for key, label in items:
            self.say(f"    {key}) {label}")
        while True:
            chosen = self.prompt("Seçim", default)
            if chosen in {key for key, _ in items}:
                return chosen
            self.say("  Geçerli bir seçenek girin.", "yellow")

    @staticmethod
    def _read_key():
        import select
        import termios
        import tty
        fd = sys.stdin.fileno()
        previous = termios.tcgetattr(fd)
        try:
            tty.setraw(fd)
            key = sys.stdin.read(1)
            if key == "\x1b":
                if select.select([sys.stdin], [], [], .08)[0]:
                    next_key = sys.stdin.read(1)
                    if next_key in ("[", "O") and select.select([sys.stdin], [], [], .08)[0]:
                        key += next_key + sys.stdin.read(1)
                    else:
                        key += next_key
            return key
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, previous)

    def _navigate(self, title, labels, initial=0, multiple=False, defaults=()):
        cursor = initial
        selected = set(defaults)
        def draw(first=False):
            if not first:
                self.stream.write(f"\033[{len(labels)+2}A\033[J")
            self.say("  " + title, "bold")
            for index, label in enumerate(labels):
                marker = "[x] " if multiple and index in selected else "[ ] " if multiple else ""
                self.say(f"  {'❯' if index == cursor else ' '} {marker}{label}",
                         'cyan' if index == cursor else None)
            self.say("  ↑/↓: gezin · Boşluk/Enter: seçin · Esc: iptal" if multiple else
                     "  ↑/↓: gezin · Enter: seçin · Esc: iptal", "dim")
        draw(True)
        while True:
            key = self._read_key()
            if key in ("\x1b[A", "\x1bOA", "k"):
                cursor = (cursor - 1) % len(labels)
            elif key in ("\x1b[B", "\x1bOB", "j"):
                cursor = (cursor + 1) % len(labels)
            elif key in ("\x03", "\x1b"):
                raise KeyboardInterrupt
            elif multiple and key in (" ", "\r", "\n"):
                if cursor == len(labels)-1:
                    if key in ("\r", "\n") and selected:
                        self.say("  Seçilen adaptörler: " + ", ".join(labels[i] for i in sorted(selected)), "green")
                        return sorted(selected)
                elif cursor in selected:
                    selected.remove(cursor)
                else:
                    selected.add(cursor)
            elif not multiple and key in ("\r", "\n"):
                return cursor
            draw()

    def choose_many(self, title, items, defaults=()):
        """Return selected item keys; interactive mode uses a checkbox list."""
        if self.tty and sys.stdin.isatty():
            indices = self._navigate(title,
                [label for _, label in items] + ["Devam et"],
                initial=len(items) if defaults else 0, multiple=True,
                defaults=[i for i, (key, _) in enumerate(items) if key in defaults])
            return [items[i][0] for i in indices]
        self.say("  " + title, "bold")
        for index, (_, label) in enumerate(items, 1):
            self.say(f"    {index}) {label}")
        while True:
            raw = self.prompt("Seçilecek sıra numaraları (örn. 1,3)")
            try:
                chosen = sorted({int(part.strip())-1 for part in raw.split(',')})
            except ValueError:
                chosen = []
            if chosen and all(0 <= index < len(items) for index in chosen):
                return [items[index][0] for index in chosen]
            self.say("  Listede görünen sıra numaralarını kullanın.", "yellow")

    def preview(self, rows):
        for key, value in rows:
            value = str(value).replace("\n", " ")
            prefix = f"  {key:<18} "
            self.say(textwrap.fill(value, width=self.width - 2, initial_indent=prefix, subsequent_indent=" " * len(prefix), break_long_words=False, break_on_hyphens=False))

    def target(self, index, total, target, addresses):
        filled = int(20 * (index-1) / total)
        self.say()
        self.say(f"  Görev: [{('#' * filled).ljust(20, '-')}] {index-1}/{total} tamamlandı · sırada {target}", "cyan")
        self.say("  IP: " + ", ".join(addresses[:5]) + (" ..." if len(addresses) > 5 else ""), "dim")

    def target_done(self, completed, total):
        filled = int(20 * completed / total)
        self.say(f"  Görev: [{('#' * filled).ljust(20, '-')}] {completed}/{total} tamamlandı", "green")

    def counted(self, name, completed, total, started):
        current=time.monotonic()
        if completed!=total and current-self._last_update < (1 if self.tty else 12):
            return
        elapsed=current-started
        pct=completed/total*100 if total else 100
        eta=int(elapsed*(total-completed)/completed) if completed else 0
        label=f"  {name}: [{('#'*int(pct/5)).ljust(20,'-')}] {completed}/{total} ({pct:.0f}%) · ~{eta} sn kaldı"
        if self.animation and completed!=total:
            self.stream.write('\r'+self.paint(label[:self.width-2].ljust(self.width-2),'cyan'))
            self.stream.flush()
        else:
            self.say(label,'cyan')
        self._last_update=current

    def tick(self, name, started, timeout=None, output=None):
        current=time.monotonic()
        interval=.25 if self.animation else 15
        if current - self._last_update < interval:
            return
        elapsed = current - started
        pct = self.scan_progress(output) if output else None
        remaining = f"tahmini {int(elapsed*(100-pct)/pct)} sn" if pct and pct < 100 else ("yakında" if pct == 100 else "bilinmiyor")
        bound = f" · süre sınırı {int(max(0,timeout-elapsed))} sn" if timeout else ""
        frame = "|/-\\"[int(elapsed * 8) % 4]
        bar = f"[{('#'*int(pct/5)).ljust(20,'-')}] {pct:.1f}%" if pct is not None else "yüzde bekleniyor"
        label = f"  {frame} {name} {bar} · {int(elapsed)} sn · kalan {remaining}{bound}"
        if self.animation:
            self.stream.write("\r" + self.paint(label[:self.width-2].ljust(self.width-2), "cyan"))
            self.stream.flush()
        elif current-self._last_log >= 15:
            self.say(label)
            self._last_log=current
        self._last_update=current

    def result(self, name, status, seconds):
        if self.animation:
            self.stream.write("\r" + " " * min(self.width - 1, 105) + "\r")
        tone = "green" if status == "ok" else "yellow" if status in ("missing_tool", "blocked", "inconclusive") else "red"
        self.say(f"  [{status.upper():12}] {name}  ({seconds:.1f} sn)", tone)

    def done(self, root, status):
        self.section(5, 5, "Tarama bitti · rapor durumu")
        self.say(f"  Durum: {status}", "green" if status == "completed" else "yellow")
        for filename in ("YONETICI_OZETI.pdf", "TEKNIK_RAPOR.pdf", "REPORT.html", "steps.json"):
            if (root / filename).is_file():
                self.say(f"  - {root / filename}")
        self.say(f"  Görev klasörü: {root}", "cyan")
        self.say("  Otomatik gözlemler analist doğrulaması bekler.", "dim")


UI = Console()
