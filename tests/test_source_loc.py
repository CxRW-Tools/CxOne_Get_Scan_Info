import os
import zipfile

import pytest

from src.operations import source_loc as sl

FILES = {
    "main.tf": 'resource "aws_s3_bucket" "b" {\n  # c\n  bucket = "x"\n}\n',
    "Dockerfile": "FROM alpine\n# c\nRUN ls\n",
    "docker-compose.yml": "services:\n  a:\n    image: x\n",
    "infra/main.bicep": "param a string\n// c\n",
    "serverless.yml": "service: s\nprovider:\n  name: aws\n",
    "Pulumi.dev.yaml": "config:\n  a: b\n",
    ".github/workflows/ci.yml": "on: push\njobs: {}\n",
    "api/svc.proto": "syntax = \"proto3\";\n",
    "chart/Chart.yaml": "name: c\n",
    "chart/templates/d.yaml": "a: b\n",
    "roles/web/tasks/main.yml": "- name: x\n  debug: msg=hi\n",
    "cf.yaml": "AWSTemplateFormatVersion: '2010-09-09'\nResources: {}\n",
    "arm.json": '{"$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#"}',
    "oas.yaml": "openapi: 3.0.0\ninfo: {}\n",
    "xp.yaml": "apiVersion: pkg.crossplane.io/v1\nkind: Provider\n",
    "kn.yaml": "apiVersion: serving.knative.dev/v1\nkind: Service\n",
    "k8s.yaml": "apiVersion: v1\nkind: Pod\n",
    "play.yml": "- hosts: all\n  tasks: []\n",
    "gdm.yaml": "resources:\n- name: vm\n  type: compute.v1.instance\n",
    "app/a.py": "# c\nx = 1\n\n",
    "README.md": "# hi\n",
}
EXPECT = {
    "main.tf": "Terraform", "Dockerfile": "Dockerfile", "docker-compose.yml": "DockerCompose",
    "infra/main.bicep": "Bicep", "serverless.yml": "ServerlessFW", "Pulumi.dev.yaml": "Pulumi",
    ".github/workflows/ci.yml": "CICD", "api/svc.proto": "GRPC", "chart/templates/d.yaml": "Helm",
    "roles/web/tasks/main.yml": "Ansible", "cf.yaml": "CloudFormation", "arm.json": "AzureResourceManager",
    "oas.yaml": "OpenAPI", "xp.yaml": "Crossplane", "kn.yaml": "Knative", "k8s.yaml": "Kubernetes",
    "play.yml": "Ansible", "gdm.yaml": "GoogleDeploymentManager",
}


@pytest.fixture
def tree(tmp_path):
    for rel, text in FILES.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    return str(tmp_path)


def test_classification_per_platform(tree):
    charts = {"chart"}
    for rel, plat in EXPECT.items():
        head = FILES[rel]
        got = sl.classify_by_name(rel, charts) or sl.classify_by_content(rel, head)
        assert got == plat, rel
    assert (sl.classify_by_name("app/a.py") or sl.classify_by_content("app/a.py", FILES["app/a.py"])) is None


def test_analyze_tree_totals(tree):
    r = sl.analyze_tree(tree)
    assert r["app_code_loc"] == 1  # only a.py "x = 1"; docs/data/IaC excluded
    assert set(r["iac_platforms"]) >= set(EXPECT.values())
    assert r["iac_platforms"]["Terraform"]["loc"] == 3  # comment excluded
    assert r["iac_loc"] > 20 and r["top_iac_files"][0]["loc"] >= r["top_iac_files"][-1]["loc"]


@pytest.mark.parametrize("family,text,expect", [
    ("c", "int a; // x\n// y\n/* z\n still */\n\ncode /* i */ more\n", (2, 3, 1)),
    ("hash", "# c\nx=1  # t\n\n", (1, 1, 1)),
    ("sql", "-- c\nselect 1;\n/* a\nb */\n", (1, 3, 0)),
    ("markup", "<!-- a\nb -->\n<p>x</p>\n", (1, 2, 0)),
    ("hcl", "# a\n// b\n/* c */\na = 1\n", (1, 3, 0)),
])
def test_comment_counting_per_family(family, text, expect):
    assert sl.count_text(text, family) == expect


def test_safe_extract_rejects_traversal_and_symlinks(tmp_path):
    z = tmp_path / "a.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("ok/a.txt", "hi")
        zf.writestr("../evil.txt", "x")
        zf.writestr("/abs.txt", "x")
        info = zipfile.ZipInfo("link")
        info.external_attr = 0o120777 << 16
        zf.writestr(info, "target")
    dest = tmp_path / "out"
    dest.mkdir()
    assert sl.safe_extract(str(z), str(dest)) == 3
    assert os.path.exists(dest / "ok" / "a.txt") and not os.path.exists(tmp_path / "evil.txt")
    assert not os.path.exists(dest / "link")


def test_redirect_validation():
    assert sl._redirect_allowed("https://eu.ast.checkmarx.net/x", "eu.ast.checkmarx.net")
    assert sl._redirect_allowed("https://bucket.s3.amazonaws.com/x", "eu.ast.checkmarx.net")
    assert not sl._redirect_allowed("http://bucket.s3.amazonaws.com/x", "eu.ast.checkmarx.net")
    assert not sl._redirect_allowed("https://169.254.169.254/x", "eu.ast.checkmarx.net")
    assert not sl._redirect_allowed("file:///etc/passwd", "eu.ast.checkmarx.net")
