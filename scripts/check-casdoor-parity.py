"""Compare explicit flat /api route declarations, not functional completeness.

Nested protocol routes, wildcard methods, middleware, request/response schemas and
business behavior need separate review. No external packages are required.
"""
import argparse
import json
from pathlib import Path
import re
import subprocess


def function_body(source, name):
    start = re.search(r"(?:pub )?fn " + name + r"\([^)]*\)[^{]*\{", source).end()
    # Router builders have no braces in strings except route parameters, which balance.
    depth = 1
    for pos in range(start, len(source)):
        depth += (source[pos] == "{") - (source[pos] == "}")
        if not depth:
            return source[start:pos]
    raise ValueError(name)


def audit(reference, project):
    upstream = (reference / "routers/router.go").read_text(encoding="utf-8")
    expected = set()
    all_paths = set()
    wildcards = []
    for path, spec in re.findall(r'web\.Router\("([^"]+)",[^\n]*?, "([^"]+)"\)', upstream):
        all_paths.add(path)
        if not re.fullmatch(r"/api/[^/]+", path):
            continue
        for operation in spec.split(";"):
            methods = operation.split(":")[0]
            for method in methods.split(","):
                if method == "*":
                    wildcards.append(path)
                else:
                    expected.add((method, path))

    routes_source = (project / "crates/casdog/src/routes.rs").read_text(encoding="utf-8")
    compat_source = (project / "crates/casdog/src/handlers/casdoor_compat.rs").read_text(encoding="utf-8")
    source = "\n".join([function_body(routes_source, "public_routes"),
                          function_body(routes_source, "protected_routes"),
                          function_body(compat_source, "routes")])
    # Pathless child router functions inherit /api; named resource routers do not.
    visited = {"public_routes", "protected_routes"}
    pending = re.findall(r"\.push\((\w+)\(\)\)", source)
    while pending:
        name = pending.pop()
        if name in visited:
            continue
        visited.add(name)
        body = function_body(routes_source, name)
        if body.lstrip().startswith("Router::new()"):
            source += "\n" + body
            pending.extend(re.findall(r"\.push\((\w+)\(\)\)", body))
    # Follow only modules actually mounted beneath /api; unmounted declarations
    # must never inflate the route inventory.
    mounted_modules = set()
    while True:
        names = set(re.findall(r"\.push\((?:crate::handlers::)?(\w+)::routes\(\)\)", source)) - mounted_modules
        if not names:
            break
        for name in sorted(names):
            mounted_modules.add(name)
            module_path = project / "crates/casdog/src/handlers" / (name + ".rs")
            if module_path.exists():
                source += "\n" + function_body(module_path.read_text(encoding="utf-8"), "routes")
    actual = set()
    declarations = list(re.finditer(r'Router::with_path\("([^"/]+)"\)', source))
    for declaration in declarations:
        # Read only adjacent method calls; nested .push calls must not count.
        tail = source[declaration.end():]
        remaining = tail
        while (method := re.match(r'\s*\.(get|post|put|delete|patch|head|options)\([^()]+\)', remaining)):
            actual.add((method.group(1).upper(), "/api/" + declaration.group(1)))
            remaining = remaining[method.end():]
    for plural, singular in re.findall(r'resource_route!\(\s*router,\s*"([^"]+)",\s*"([^"]+)"', source):
        actual.add(("GET", "/api/get-" + plural))
        actual.add(("GET", "/api/get-" + singular))
        actual.update(("POST", "/api/" + verb + "-" + singular) for verb in ["add", "update", "delete"])

    format_route = lambda item: f"{item[0]} {item[1]}"
    revision = subprocess.check_output(["git", "-C", str(reference), "rev-parse", "HEAD"], text=True).strip()
    return {
        "reference_revision": revision,
        "scope": "Explicit single-segment /api routes with concrete HTTP methods; static declarations only, not behavior or authorization parity.",
        "upstream_all_explicit_unique_paths": len(all_paths),
        "upstream_flat_method_pairs": len(expected),
        "matched_flat_method_pairs": len(expected & actual),
        "missing_flat_method_pairs": len(expected - actual),
        "coverage_percent": round(100 * len(expected & actual) / len(expected), 2),
        "missing": sorted(map(format_route, expected - actual)),
        "wildcard_flat_routes_excluded": sorted(set(wildcards)),
        "nested_and_non_api_paths_excluded": sorted(path for path in all_paths if not re.fullmatch(r"/api/[^/]+", path)),
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference", type=Path, default=Path("E:/Repos/casdoor"))
    parser.add_argument("--project", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = json.dumps(audit(args.reference, args.project), indent=2, ensure_ascii=False)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(result + "\n", encoding="utf-8")
    print(result)
