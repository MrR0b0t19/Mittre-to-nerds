import argparse
import atexit
import json
import os
import tempfile

import requests
from mitreattack.stix20 import MitreAttackData
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.tree import Tree
from rich.text import Text
from rich.rule import Rule
from rich.theme import Theme
from rich.markdown import Markdown
from rich import box

BASE = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master"
_TEMP_FILES = []

# Paleta
THEME = Theme({
    "tech.id": "bold cyan",
    "tech.name": "bold white",
    "ds.id": "bold magenta",
    "ds.name": "bold yellow",
    "an.id": "bold green",
    "an.name": "green",
    "muted": "dim white",
    "label": "bold blue",
    "error": "bold red",
    "warn": "bold yellow",
    "ok": "bold green",
})

console = Console(theme=THEME)


def _cleanup_temp_files():
    for path in _TEMP_FILES:
        try:
            os.unlink(path)
        except OSError:
            pass


atexit.register(_cleanup_temp_files)

#mas info de uso en la documentacion xD
def load_attack(domain="enterprise-attack", version="19.1"):
    url = f"{BASE}/{domain}/{domain}-{version}.json"

    with console.status(
        f"[bold cyan]Descargando ATT&CK[/] [white]{domain}[/] [muted]v{version}[/]…",
        spinner="dots",
    ):
        r = requests.get(url, timeout=60)
        r.raise_for_status()
        bundle = r.json()

    with tempfile.NamedTemporaryFile(
        mode="w",
        suffix=".json",
        delete=False,
        encoding="utf-8",
    ) as f:
        json.dump(bundle, f)
        temp_path = f.name

    _TEMP_FILES.append(temp_path)

    with console.status("[bold cyan]Cargando datos STIX…", spinner="dots"):
        data = MitreAttackData(temp_path)

    console.print(
        f"[ok]:3[/] ATT&CK cargado: [white]{domain}[/] "
        f"[muted]({version})[/]\n"
    )
    return data


def clean(objects):
    return [
        o for o in objects
        if o
        and not o.get("revoked", False)
        and not o.get("x_mitre_deprecated", False)
    ]


def attack_id(obj):
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None


def find_by_attack_id(src, ext_id, stix_type=None):
    if not stix_type:
        raise ValueError("stix_type is required")

    obj = src.get_object_by_attack_id(ext_id, stix_type)
    if not obj:
        return None

    if isinstance(obj, list):
        results = clean(obj)
        results = [o for o in results if o.get("type") == stix_type]
        return results[0] if results else None

    if obj.get("revoked", False) or obj.get("x_mitre_deprecated", False):
        return None

    if obj.get("type") != stix_type:
        return None

    return obj


def get_object(src, stix_id):
    try:
        obj = src.get_object_by_stix_id(stix_id)
        if obj and not obj.get("revoked", False) and not obj.get("x_mitre_deprecated", False):
            return obj
    except Exception:
        pass
    return None


def get_detection_strategies_for_ttp(src, ttp_attack_id):
    technique = find_by_attack_id(src, ttp_attack_id, "attack-pattern")
    if not technique:
        raise ValueError(f"Technique {ttp_attack_id} not found")

    strategies = []
    seen = set()

    try:
        mapping = src.get_all_detection_strategies_detecting_all_techniques()
        entries = mapping.get(technique["id"], [])

        for entry in entries:
            ds = entry.get("object")
            if not ds:
                continue
            if ds.get("revoked", False) or ds.get("x_mitre_deprecated", False):
                continue
            if ds["id"] in seen:
                continue
            seen.add(ds["id"])
            strategies.append(ds)

        return technique, strategies
    except Exception:
        pass

    relationships = clean(src.get_objects_by_type("relationship"))

    for rel in relationships:
        other_id = None

        if rel.get("source_ref") == technique["id"]:
            other_id = rel.get("target_ref")
        elif rel.get("target_ref") == technique["id"]:
            other_id = rel.get("source_ref")
        else:
            continue

        other = get_object(src, other_id)
        if not other:
            continue

        if other.get("type") == "x-mitre-detection-strategy":
            if other["id"] in seen:
                continue
            seen.add(other["id"])
            strategies.append(other)

    return technique, strategies


def resolve_analytics(src, detection_strategy):
    try:
        analytics = src.get_analytics_by_detection_strategy(
            detection_strategy["id"],
            remove_revoked_deprecated=True,
        )
        return clean(analytics)
    except Exception:
        analytics = []
        for analytic_ref in detection_strategy.get("x_mitre_analytic_refs", []):
            analytic = get_object(src, analytic_ref)
            if analytic:
                analytics.append(analytic)
        return analytics


def _fmt_description(text: str | None) -> str:
    if not text or not text.strip():
        return "[muted]— sin descripcion en el objeto STIX —[/]"
    return text.strip()


def render_technique(technique) -> None:
    tid = attack_id(technique) or "?"
    name = technique.get("name", "?")
    desc = _fmt_description(technique.get("description"))

    header = Text()
    header.append("TECNICA  ", style="label")
    header.append(f"{tid}", style="tech.id")
    header.append("  ·  ", style="muted")
    header.append(name, style="tech.name")

    body = Text()
    body.append(desc, style="white")

    console.print(
        Panel(
            body,
            title=header,
            title_align="left",
            border_style="cyan",
            box=box.ROUNDED,
            padding=(1, 2),
        )
    )


def render_strategy(ds, analytics) -> None:
    ds_id = attack_id(ds) or "?"
    ds_name = ds.get("name", "?")
    stix_id = ds.get("id", "?")
    desc = _fmt_description(ds.get("description"))

    title = Text()
    title.append("DETECTION STRATEGY  ", style="label")
    title.append(f"{ds_id}", style="ds.id")
    title.append("  ·  ", style="muted")
    title.append(ds_name, style="ds.name")

    meta = Table.grid(padding=(0, 1))
    meta.add_column(style="label", no_wrap=True)
    meta.add_column(style="white")
    meta.add_row("STIX ID", stix_id)
    meta.add_row("Descripción", desc)

    console.print(
        Panel(
            meta,
            title=title,
            title_align="left",
            border_style="magenta",
            box=box.ROUNDED,
            padding=(1, 2),
        )
    )

    if not analytics:
        console.print("  [warn][/] [muted]No hay analiticas vinculadas.[/]\n")
        return

    tree = Tree(
        f"[bold]Analíticas vinculadas[/] [muted]({len(analytics)})[/]",
        guide_style="green",
    )

    for an in analytics:
        an_id = attack_id(an) or "?"
        an_name = an.get("name", "?")
        an_desc = _fmt_description(an.get("description"))

        label = Text()
        label.append(f"{an_id}", style="an.id")
        label.append("  ·  ", style="muted")
        label.append(an_name, style="an.name")

        branch = tree.add(label)
        branch.add(Text(an_desc, style="white"))

    console.print(tree)
    console.print()


def render_summary(domain: str, version: str, technique, strategies) -> None:
    table = Table(
        title="Resumen",
        box=box.SIMPLE_HEAVY,
        title_style="bold white",
        header_style="bold blue",
        show_lines=False,
    )
    table.add_column("Campo", style="label", no_wrap=True)
    table.add_column("Valor", style="white")

    table.add_row("Dominio", domain)
    table.add_row("Version ATT&CK", version)
    table.add_row("T3cnica", f"{attack_id(technique)} — {technique.get('name', '?')}")
    table.add_row("Estrategias encontradas", str(len(strategies)))
    table.add_row("HOKMA - 2026 - APT Village")

    console.print(table)

def main():
    parser = argparse.ArgumentParser(
        description="Retrieve ATT&CK detection strategies for a given technique ID. - Hokma"
    )
    parser.add_argument("technique_id", help="ATT&CK technique ID, for example T1003")
    parser.add_argument(
        "--domain",
        default="enterprise-attack",
        help="ATT&CK domain to query, default: enterprise-attack",
    )
    parser.add_argument(
        "--version",
        default="19.1",
        help="ATT&CK STIX bundle version, default: 19.1",
    )

    args = parser.parse_args()

    console.rule("[bold cyan]MITRE ATT&CK & Detection Strategies[/]", style="cyan")

    try:
        src = load_attack(args.domain, args.version)
        technique, strategies = get_detection_strategies_for_ttp(src, args.technique_id)
    except requests.HTTPError as e:
        console.print(f"[error]x Error HTTP al descargar ATT&CK:[/] {e}")
        raise SystemExit(1)
    except ValueError as e:
        console.print(f"[error]x {e}[/]")
        raise SystemExit(1)

    render_technique(technique)
    console.print()

    if not strategies:
        console.print(
            Panel(
                "[warn]No se encontraron detection strategies para esta tecnica.[/]",
                border_style="yellow",
                box=box.ROUNDED,
            )
        )
        render_summary(args.domain, args.version, technique, strategies)
        return

    console.rule(
        f"[bold magenta]Detection Strategies[/] [muted]({len(strategies)})[/]",
        style="magenta",
    )
    console.print()

    for ds in strategies:
        analytics = resolve_analytics(src, ds)
        render_strategy(ds, analytics)

    render_summary(args.domain, args.version, technique, strategies)


if __name__ == "__main__":
    main()
