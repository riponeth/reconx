import argparse
import asyncio
import sys
import time
from datetime import datetime
import json

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box
from pathlib import Path

from config import VERSION
from modules.subdomain import enumerate_subdomains
from modules.dns_resolver import resolve_domains
from modules.port_scanner import scan_ports
from modules.http_fingerprint import fingerprint_hosts
from modules.api_discovery import discover_api_endpoints
from modules.graphql_probe import probe_graphql
from modules.content_discovery import discover_content
from modules.summary import render_summary, export_json

console = Console()

BANNER = r"""
  ____                     __  __
 |  _ \ ___  ___ ___  _ __ \ \/ /
 | |_) / _ \/ __/ _ \| '_ \ \  /
 |  _ <  __/ (_| (_) | | | | /  \
 |_| \_\___|\___\___/|_| |_|/_/\_\
"""


def phase_header(num: str, name: str, start_time: float) -> None:
    elapsed = time.time() - start_time
    console.print()
    console.rule(
        f"[bold cyan] {num} [/bold cyan][dim]▸[/dim][bold] {name} [/bold]"
        f"[dim](+{elapsed:.1f}s)[/dim]"
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="reconx",
        description=f"ReconX v{VERSION} — Web & API Recon Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--target", required=True, help="Target domain (e.g. example.com)")
    parser.add_argument("--threads", type=int, default=100, help="Concurrency (default: 100)")
    parser.add_argument("--timeout", type=int, default=5, help="HTTP timeout seconds (default: 5)")
    parser.add_argument(
        "--modules",
        nargs="+",
        default="all",
        help="Modules: subdomain dns ports http api graphql content (default: all)",
    )
    # ``--output`` is enabled by default; ``--no-output`` disables JSON export.
    parser.add_argument(
        "--output",
        action="store_true",
        default=True,
        help="Save results to a JSON file (default: true)",
    )
    parser.add_argument(
        "--no-output",
        action="store_false",
        dest="output",
        help="Disable JSON output",
    )
    parser.add_argument("--no-brute", action="store_true", help="Skip subdomain brute force")
    parser.add_argument(
        "--max-subdomains",
        type=int,
        default=2000,
        help="Cap total subdomains before DNS phase (default: 2000, 0 = unlimited)",
    )
    return parser.parse_args()


async def main() -> None:
    args = parse_args()
    start_time = time.time()
    target = (
        args.target.strip()
        .lower()
        .replace("https://", "")
        .replace("http://", "")
        .rstrip("/")
    )

    console.print(f"[bold cyan]{BANNER}[/bold cyan]", highlight=False)

    meta = Table.grid(padding=(0, 2))
    meta.add_column(style="dim")
    meta.add_column(style="bold white")
    meta.add_row("Version", f"v{VERSION}")
    meta.add_row("Target", f"[cyan]{target}[/cyan]")
    meta.add_row("Threads", str(args.threads))
    meta.add_row("Timeout", f"{args.timeout}s")
    meta.add_row("Brute force", "[dim]disabled[/dim]" if args.no_brute else "enabled")
    meta.add_row("Started", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    if args.output:
        # Rich tables require renderable objects; convert the boolean flag to a string.
        meta.add_row("Output", str(args.output))

    console.print(
        Panel(meta, title="[bold cyan]ReconX[/bold cyan]", border_style="cyan", expand=False)
    )

    results: dict = {}
    max_subs = getattr(args, "max_subdomains", 2000)

    try:
        phase_header("01", "Subdomain Enumeration", start_time)
        subdomains = await enumerate_subdomains(
            target,
            threads=args.threads,
            no_brute=args.no_brute,
            max_subdomains=max_subs,
        )
        results["subdomains"] = subdomains

        phase_header("02", "DNS Resolution", start_time)
        live_hosts = await resolve_domains(subdomains, threads=args.threads)
        results["live_hosts"] = live_hosts

        if not live_hosts:
            console.print("[yellow]No live hosts — skipping remaining phases.[/yellow]")
        else:
            phase_header("03", "Port Scanning", start_time)
            ports = await scan_ports(live_hosts, timeout=args.timeout)
            results["open_ports"] = ports

            # Only pass hosts with at least one open web port to HTTP phases.
            # This drops SMTP/MX/NS/etc. hosts that will just timeout.
            ports_map = {p["host"]: p.get("open_ports", []) for p in ports}
            web_hosts = [h for h in live_hosts if ports_map.get(h["host"])]
            skipped = len(live_hosts) - len(web_hosts)
            if skipped:
                console.print(
                    f"[dim]  {skipped} host(s) with no open web ports — "
                    f"skipped for phases 4-7[/dim]"
                )

            phase_header("04", "HTTP Fingerprinting", start_time)
            fingerprints = await fingerprint_hosts(
                web_hosts, timeout=args.timeout, threads=args.threads
            )
            results["fingerprints"] = fingerprints

            phase_header("05", "API Endpoint Discovery", start_time)
            api_endpoints = await discover_api_endpoints(
                web_hosts, timeout=args.timeout, threads=args.threads
            )
            results["api_endpoints"] = api_endpoints

            phase_header("06", "GraphQL Detection", start_time)
            graphql = await probe_graphql(
                web_hosts, timeout=args.timeout, threads=args.threads
            )
            results["graphql"] = graphql

            phase_header("07", "Content Discovery", start_time)
            content = await discover_content(
                web_hosts, timeout=args.timeout, threads=args.threads
            )
            results["content"] = content

        total_time = time.time() - start_time
        console.print()
        console.rule(
            f"[bold green] COMPLETE [/bold green][dim]— {total_time:.1f}s total[/dim]"
        )
        render_summary(results, total_time=total_time)

        # -----------------------------------------------------------------
        # Post‑scan file generation
        # -----------------------------------------------------------------
        # Create a folder named after the target domain (e.g. "example.com")
        target_dir = Path(target)
        target_dir.mkdir(parents=True, exist_ok=True)

        # Helper to write a list of lines to a file (UTF‑8)
        def _write_lines(file_path: Path, lines: list[str]) -> None:
            try:
                file_path.write_text("\n".join(lines), encoding="utf-8")
            except Exception as e:
                console.print(f"[red]Failed to write {file_path}: {e}[/red]")

        # 1. subdomains.txt
        _write_lines(target_dir / "subdomain.txt", results.get("subdomains", []))

        # 2. live-host.txt (host ip per line)
        live_hosts = results.get("live_hosts", [])
        _write_lines(
            target_dir / "live-host.txt",
            [f"{h['host']} {h['ip']}" for h in live_hosts],
        )

        # 3. open-ports.txt – group ports per host for readability
        ports = results.get("open_ports", [])
        port_lines: list[str] = []
        for entry in ports:
            host = entry.get("host")
            open_ports = entry.get("open_ports", [])
            if open_ports:
                # Example: "vpn.21viptaka.com: 80, 443, 8080"
                port_str = ", ".join(str(p) for p in open_ports)
                port_lines.append(f"{host}: {port_str}")
        _write_lines(target_dir / "open-ports.txt", port_lines)

        # 4. fingerprints.txt – human‑readable summary per host
        fingerprints = results.get("fingerprints", [])
        fp_lines: list[str] = []
        for fp in fingerprints:
            host = fp.get("host", "")
            server = fp.get("server", "")
            waf = fp.get("waf") or "-"
            missing = ", ".join(fp.get("missing_security_headers", [])) or "-"
            cookies = ", ".join(c.get("name") for c in fp.get("cookies", [])) or "-"
            line = (
                f"{host} | Server: {server} | WAF: {waf} | "
                f"MissingHeaders: {missing} | Cookies: {cookies}"
            )
            fp_lines.append(line)
        _write_lines(target_dir / "fingerprints.txt", fp_lines)

        # 5. api-endpoints.txt – flatten swagger, JS and fuzzed endpoints
        api_lines: list[str] = []
        api_data = results.get("api_endpoints", {})
        for host, sections in api_data.items():
            # swagger docs URLs
            for url in sections.get("swagger_docs", []):
                api_lines.append(url)
            # JS‑extracted URLs
            for url in sections.get("js_extracted", []):
                api_lines.append(url)
            # fuzzed endpoint dicts
            for entry in sections.get("fuzzed_endpoints", []):
                endpoint = entry.get("endpoint")
                if endpoint:
                    api_lines.append(endpoint)
        _write_lines(target_dir / "api-endpoints.txt", api_lines)

        # 6. graphql.txt – list all discovered GraphQL endpoint URLs
        graphql_lines: list[str] = []
        for entry in results.get("graphql", []):
            for url in entry.get("endpoints", []):
                graphql_lines.append(url)
        _write_lines(target_dir / "graphql.txt", graphql_lines)

        # 7. content-discovery.txt – formatted per‑host sections
        content_lines: list[str] = []
        for host, data in results.get("content", {}).items():
            lines: list[str] = []
            lines.append(f"Host: {host}")
            # Robots
            robots = data.get("robots", {})
            disallowed = robots.get("disallowed", [])
            sitemaps = robots.get("sitemap_urls", [])
            if disallowed:
                lines.append("  Robots Disallowed:")
                for path in disallowed:
                    lines.append(f"    - {path}")
            if sitemaps:
                lines.append("  Robots Sitemaps:")
                for url in sitemaps:
                    lines.append(f"    - {url}")
            # Sensitive paths
            sensitive = data.get("sensitive_paths", [])
            if sensitive:
                lines.append("  Sensitive Paths:")
                for item in sensitive:
                    path = item.get("path")
                    status = item.get("status")
                    lines.append(f"    - {path} (status {status})")
            # Well‑known
            well_known = data.get("well_known", [])
            if well_known:
                lines.append("  .well-known:")
                for wk in well_known:
                    wk_path = wk.get("path")
                    wk_status = wk.get("status")
                    lines.append(f"    - {wk_path} (status {wk_status})")
            # Separate hosts with a blank line
            content_lines.extend(lines)
            content_lines.append("")
        _write_lines(target_dir / "content-discovery.txt", content_lines)

        # 8. critical-findings.txt – expose only sensitive paths (status != 404/410)
        critical_lines: list[str] = []
        for host, data in results.get("content", {}).items():
            for item in data.get("sensitive_paths", []):
                if item.get("status") not in [404, 410]:
                    critical_lines.append(f"{host}:{item.get('path')} ({item.get('status')})")
        _write_lines(target_dir / "critical-findings.txt", critical_lines)

        # -----------------------------------------------------------------
        # JSON export (if enabled) – store inside the domain folder
        # -----------------------------------------------------------------
        if args.output:
            # Save JSON with the domain name inside the domain folder
            json_path = target_dir / f"{target}.json"
            export_json(results, str(json_path))
            console.print(f"\n[green]Results saved →[/green] {json_path}")

    except asyncio.CancelledError:
        _interrupted(results, start_time, args)


def _interrupted(results: dict, start_time: float, args: argparse.Namespace) -> None:
    elapsed = time.time() - start_time
    console.print(
        f"\n[bold yellow]Scan interrupted[/bold yellow] [dim]after {elapsed:.1f}s[/dim]"
    )
    if results:
        render_summary(results, total_time=elapsed)
        if getattr(args, "output", None):
            # Write the partial JSON using the domain name inside the same folder.
            target_dir = Path(
                args.target.strip()
                .lower()
                .replace("https://", "")
                .replace("http://", "")
                .rstrip("/")
            )
            target_dir.mkdir(parents=True, exist_ok=True)
            json_path = target_dir / f"{target_dir.name}.json"
            export_json(results, str(json_path))
            console.print(f"[green]Partial results saved →[/green] {json_path}")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        console.print("\n[bold yellow]Interrupted.[/bold yellow]")
        sys.exit(0)
