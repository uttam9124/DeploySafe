import argparse
import json
import re
from pathlib import Path
from datetime import datetime, timezone


def add_finding(findings, rule, points, message, file_name, line=None):
    findings.append({
        "rule": rule,
        "risk_points": points,
        "message": message,
        "file": file_name,
        "line": line
    })


def analyze_dockerfile(path, findings):
    content = path.read_text()
    lines = content.splitlines()
    file_name = str(path)

    has_user = False
    has_healthcheck = False

    for number, line in enumerate(lines, start=1):
        stripped = line.strip()

        if not stripped or stripped.startswith("#"):
            continue

        if re.match(r"^USER\s+", stripped, re.I):
            has_user = True

            if re.match(r"^USER\s+root\b", stripped, re.I):
                add_finding(
                    findings, "DOCKER_ROOT_USER", 20,
                    "Container explicitly runs as root.",
                    file_name, number
                )

        if re.match(r"^HEALTHCHECK\s+", stripped, re.I):
            has_healthcheck = True

        if re.match(r"^FROM\s+\S+:latest\b", stripped, re.I):
            add_finding(
                findings, "DOCKER_LATEST_IMAGE", 15,
                "Docker image uses the latest tag.",
                file_name, number
            )

        if re.match(r"^ADD\s+", stripped, re.I):
            add_finding(
                findings, "DOCKER_ADD_INSTRUCTION", 5,
                "Review ADD instruction; COPY is safer for ordinary file copies.",
                file_name, number
            )

        if re.match(r"^(ENV|ARG)\s+", stripped, re.I):
            if re.search(
                r"(API_KEY|PASSWORD|TOKEN|SECRET)\s*=\s*\S+",
                stripped,
                re.I
            ):
                add_finding(
                    findings, "HARDCODED_SECRET", 30,
                    "Possible hardcoded secret detected. Value is not displayed.",
                    file_name, number
                )

    if not has_user:
        add_finding(
            findings, "DOCKER_USER_MISSING", 20,
            "No USER instruction found; container may run as root.",
            file_name
        )

    if not has_healthcheck:
        add_finding(
            findings, "DOCKER_HEALTHCHECK_MISSING", 10,
            "Dockerfile does not define a HEALTHCHECK.",
            file_name
        )


def analyze_deployment(path, findings):
    content = path.read_text()
    lines = content.splitlines()
    file_name = str(path)

    def find_line(pattern):
        for number, line in enumerate(lines, start=1):
            if re.search(pattern, line, re.I):
                return number
        return None

    replicas = re.search(
        r"(?m)^\s*replicas\s*:\s*(\d+)",
        content
    )

    if replicas and int(replicas.group(1)) == 0:
        add_finding(
            findings, "ZERO_REPLICAS", 40,
            "Deployment has zero replicas.",
            file_name, find_line(r"^\s*replicas\s*:")
        )

    if re.search(r"(?m)^\s*image\s*:\s*\S+:latest\s*$", content):
        add_finding(
            findings, "K8S_LATEST_IMAGE", 15,
            "Kubernetes container image uses the latest tag.",
            file_name, find_line(r"^\s*image\s*:")
        )

    if re.search(r"(?m)^\s*privileged\s*:\s*true\s*$", content, re.I):
        add_finding(
            findings, "PRIVILEGED_CONTAINER", 30,
            "Privileged container access is enabled.",
            file_name, find_line(r"^\s*privileged\s*:")
        )

    if re.search(r"(?m)^\s*runAsNonRoot\s*:\s*false\s*$", content, re.I):
        add_finding(
            findings, "ROOT_EXECUTION_ALLOWED", 20,
            "Configuration explicitly allows root execution.",
            file_name, find_line(r"^\s*runAsNonRoot\s*:")
        )

    if not re.search(r"(?m)^\s*limits\s*:", content):
        add_finding(
            findings, "RESOURCE_LIMITS_MISSING", 10,
            "Container resource limits are missing.",
            file_name
        )

    if not re.search(r"(?m)^\s*readinessProbe\s*:", content):
        add_finding(
            findings, "READINESS_PROBE_MISSING", 10,
            "Readiness probe is missing.",
            file_name
        )

    if not re.search(r"(?m)^\s*livenessProbe\s*:", content):
        add_finding(
            findings, "LIVENESS_PROBE_MISSING", 10,
            "Liveness probe is missing.",
            file_name
        )


def calculate_risk(findings):
    raw_score = sum(item["risk_points"] for item in findings)
    score = min(raw_score, 100)

    if score < 30:
        level = "LOW"
        decision = "ALLOW"
    elif score < 60:
        level = "MEDIUM"
        decision = "REVIEW"
    else:
        level = "HIGH"
        decision = "BLOCK"

    return score, level, decision


def main():
    parser = argparse.ArgumentParser(
        description="DeploySafe Deployment Risk Analyzer"
    )

    parser.add_argument(
        "--dockerfile",
        default="sample_app/Dockerfile"
    )

    parser.add_argument(
        "--deployment",
        default="sample_app/deployment.yaml"
    )

    parser.add_argument(
        "--output",
        default="reports/deploysafe-report.json"
    )

    parser.add_argument(
        "--fail-on-high",
        action="store_true"
    )

    args = parser.parse_args()

    dockerfile = Path(args.dockerfile)
    deployment = Path(args.deployment)
    output = Path(args.output)

    for path in (dockerfile, deployment):
        if not path.is_file():
            parser.error(f"Required file not found: {path}")

    findings = []

    analyze_dockerfile(dockerfile, findings)
    analyze_deployment(deployment, findings)

    score, level, decision = calculate_risk(findings)

    report = {
        "project": "DeploySafe",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "risk_score": score,
        "risk_level": level,
        "deployment_decision": decision,
        "total_findings": len(findings),
        "findings": findings
    }

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=4))

    print("\n====================================")
    print("       DEPLOYSAFE RISK REPORT")
    print("====================================")
    print(f"Risk Score       : {score}/100")
    print(f"Risk Level       : {level}")
    print(f"Decision         : {decision}")
    print(f"Total Findings   : {len(findings)}")
    print("------------------------------------")

    for finding in findings:
        print(
            f"[{finding['rule']}] "
            f"+{finding['risk_points']} points"
        )
        print(f"  {finding['message']}")

    print("------------------------------------")
    print(f"Report saved to: {output}")
    print("====================================\n")

    if args.fail_on_high and level == "HIGH":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
