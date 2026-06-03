import base64
import json
import os
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import Any, Dict, Optional


GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")
GITHUB_OWNER = os.getenv("GITHUB_OWNER", "andrewferdinandus")
GITHUB_REPO = os.getenv("GITHUB_REPO", "aks-gitops-sample-app")
GITHUB_BASE_BRANCH = os.getenv("GITHUB_BASE_BRANCH", "aiops-lab-03-github-pr-remediation")
GITHUB_PR_BRANCH_PREFIX = os.getenv("GITHUB_PR_BRANCH_PREFIX", "aiops-remediation")
GITHUB_API_URL = os.getenv("GITHUB_API_URL", "https://api.github.com")


def github_api_request(method: str, path: str, body: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    if not GITHUB_TOKEN:
        raise RuntimeError("GITHUB_TOKEN is not configured.")

    url = f"{GITHUB_API_URL}{path}"
    data = None
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "aks-aiops-controller",
    }

    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"

    request = urllib.request.Request(url, data=data, method=method, headers=headers)

    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            raw = response.read().decode("utf-8")
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8")
        raise RuntimeError(f"GitHub API error {exc.code}: {raw[:1000]}") from exc


def get_github_file(path: str, branch: str) -> Dict[str, Any]:
    encoded_path = urllib.parse.quote(path)
    encoded_branch = urllib.parse.quote(branch)

    return github_api_request(
        "GET",
        f"/repos/{GITHUB_OWNER}/{GITHUB_REPO}/contents/{encoded_path}?ref={encoded_branch}",
    )


def decode_github_content(file_obj: Dict[str, Any]) -> str:
    content = file_obj.get("content", "")
    content = content.replace("\n", "")
    return base64.b64decode(content.encode("utf-8")).decode("utf-8")


def encode_github_content(content: str) -> str:
    return base64.b64encode(content.encode("utf-8")).decode("utf-8")


def normalize_value(value: Any) -> str:
    if isinstance(value, dict):
        return value.get("app", json.dumps(value, sort_keys=True))
    return str(value)


def build_fixed_file_content(original: str, patch: Dict[str, Any]) -> str:
    file_path = patch.get("file", "")
    current_text = normalize_value(patch.get("current_value", ""))
    expected_text = normalize_value(patch.get("expected_value", ""))

    if file_path.endswith("service.yaml"):
        old = f"""spec:
  type: ClusterIP
  selector:
    app: {current_text}
"""
        new = f"""spec:
  type: ClusterIP
  selector:
    app: {expected_text}
"""
        if old in original:
            return original.replace(old, new)

    if file_path.endswith("deployment.yaml"):
        old = f"          image: {current_text}"
        new = f"          image: {expected_text}"
        if old in original:
            return original.replace(old, new)

    if current_text and current_text in original:
        return original.replace(current_text, expected_text, 1)

    raise RuntimeError("Could not apply patch recommendation to GitHub file content.")


def build_pull_request_body(report: Dict[str, Any], patch: Dict[str, Any]) -> str:
    diff_text = patch.get("diff", "")

    return f"""## AIOps remediation recommendation

The AIOps controller detected an incident and generated a GitOps-safe remediation patch.

Incident type: {report.get("incident_type", "unknown")}
Affected resource: {report.get("affected_resource", "unknown")}
File: {patch.get("file", "unknown")}
Field: {patch.get("field", "unknown")}
Current value: {patch.get("current_value", "unknown")}
Expected value: {patch.get("expected_value", "unknown")}
Confidence: {report.get("confidence", "unknown")}

## Root cause

{report.get("root_cause", "No root cause was provided.")}

## Recommended patch

DIFF START
{diff_text}
DIFF END

## Safety

- Human review is required.
- This PR was not auto-merged.
- The controller did not patch the Kubernetes cluster directly.
- Apply this change only through the GitOps workflow.
"""


def create_pr_from_report(report: Dict[str, Any]) -> Dict[str, Any]:
    patch = report.get("patch_recommendation") or {}

    if not GITHUB_TOKEN:
        return {
            "status": "disabled",
            "reason": "GITHUB_TOKEN is not configured.",
            "human_review_required": True,
            "auto_merge": "not_performed",
            "direct_cluster_changes": "not_performed",
        }

    if not patch.get("file") or not patch.get("diff"):
        return {
            "status": "skipped",
            "reason": "No patch recommendation is available.",
            "human_review_required": True,
            "auto_merge": "not_performed",
            "direct_cluster_changes": "not_performed",
        }

    try:
        file_path = patch["file"]
        incident_type = report.get("incident_type", "incident")
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
        new_branch = f"{GITHUB_PR_BRANCH_PREFIX}/{incident_type}-{timestamp}"

        base_ref = github_api_request(
            "GET",
            f"/repos/{GITHUB_OWNER}/{GITHUB_REPO}/git/ref/heads/{urllib.parse.quote(GITHUB_BASE_BRANCH)}",
        )
        base_sha = base_ref["object"]["sha"]

        github_api_request(
            "POST",
            f"/repos/{GITHUB_OWNER}/{GITHUB_REPO}/git/refs",
            {
                "ref": f"refs/heads/{new_branch}",
                "sha": base_sha,
            },
        )

        file_obj = get_github_file(file_path, new_branch)
        original = decode_github_content(file_obj)
        fixed = build_fixed_file_content(original, patch)

        if fixed == original:
            return {
                "status": "skipped",
                "reason": "Generated file content is identical to the base branch.",
                "branch": new_branch,
                "file": file_path,
                "human_review_required": True,
                "auto_merge": "not_performed",
                "direct_cluster_changes": "not_performed",
            }

        github_api_request(
            "PUT",
            f"/repos/{GITHUB_OWNER}/{GITHUB_REPO}/contents/{urllib.parse.quote(file_path)}",
            {
                "message": f"Fix {incident_type} with AIOps recommendation",
                "content": encode_github_content(fixed),
                "sha": file_obj["sha"],
                "branch": new_branch,
            },
        )

        title = f"AIOps remediation: {incident_type}"
        body = build_pull_request_body(report, patch)

        pr = github_api_request(
            "POST",
            f"/repos/{GITHUB_OWNER}/{GITHUB_REPO}/pulls",
            {
                "title": title,
                "head": new_branch,
                "base": GITHUB_BASE_BRANCH,
                "body": body,
            },
        )

        return {
            "status": "created",
            "url": pr.get("html_url"),
            "number": pr.get("number"),
            "branch": new_branch,
            "base_branch": GITHUB_BASE_BRANCH,
            "file": file_path,
            "human_review_required": True,
            "auto_merge": "not_performed",
            "direct_cluster_changes": "not_performed",
        }

    except Exception as exc:
        return {
            "status": "error",
            "reason": str(exc),
            "human_review_required": True,
            "auto_merge": "not_performed",
            "direct_cluster_changes": "not_performed",
        }
