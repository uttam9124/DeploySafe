from analyzer.risk_analyzer import (
    calculate_risk,
    analyze_dockerfile,
    analyze_deployment
)


def test_low_risk():
    score, level, decision = calculate_risk([])
    assert score == 0
    assert level == "LOW"
    assert decision == "ALLOW"


def test_medium_risk():
    findings = [{"risk_points": 30}]
    score, level, decision = calculate_risk(findings)
    assert score == 30
    assert level == "MEDIUM"
    assert decision == "REVIEW"


def test_high_risk():
    findings = [{"risk_points": 60}]
    score, level, decision = calculate_risk(findings)
    assert score == 60
    assert level == "HIGH"
    assert decision == "BLOCK"


def test_score_cannot_exceed_100():
    findings = [{"risk_points": 150}]
    score, level, decision = calculate_risk(findings)
    assert score == 100
    assert level == "HIGH"
    assert decision == "BLOCK"


def test_dockerfile_security_detection(tmp_path):
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(
        "FROM python:latest\n"
        "USER root\n"
        "ENV API_KEY=demo-secret\n"
        "ADD app.py /app/app.py\n"
    )

    findings = []
    analyze_dockerfile(dockerfile, findings)

    rules = {item["rule"] for item in findings}

    assert "DOCKER_LATEST_IMAGE" in rules
    assert "DOCKER_ROOT_USER" in rules
    assert "HARDCODED_SECRET" in rules
    assert "DOCKER_ADD_INSTRUCTION" in rules
    assert "DOCKER_HEALTHCHECK_MISSING" in rules


def test_deployment_security_detection(tmp_path):
    deployment = tmp_path / "deployment.yaml"
    deployment.write_text(
        "spec:\n"
        "  replicas: 0\n"
        "  template:\n"
        "    spec:\n"
        "      containers:\n"
        "        - name: app\n"
        "          image: app:latest\n"
        "          securityContext:\n"
        "            privileged: true\n"
        "            runAsNonRoot: false\n"
    )

    findings = []
    analyze_deployment(deployment, findings)

    rules = {item["rule"] for item in findings}

    assert "ZERO_REPLICAS" in rules
    assert "K8S_LATEST_IMAGE" in rules
    assert "PRIVILEGED_CONTAINER" in rules
    assert "ROOT_EXECUTION_ALLOWED" in rules
    assert "RESOURCE_LIMITS_MISSING" in rules
    assert "READINESS_PROBE_MISSING" in rules
    assert "LIVENESS_PROBE_MISSING" in rules
