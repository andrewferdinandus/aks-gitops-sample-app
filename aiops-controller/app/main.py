import asyncio
import html
import json
import os
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse
from kubernetes import client, config
from kubernetes.client.rest import ApiException
from openai import AzureOpenAI

from app.github_pr import create_pr_from_report


WATCH_NAMESPACE = os.getenv("WATCH_NAMESPACE", "incident-demo")
AIOPS_NAMESPACE = os.getenv("AIOPS_NAMESPACE", "aiops-system")
REPORT_CONFIGMAP = os.getenv("REPORT_CONFIGMAP", "aiops-latest-incident-report")

AZURE_OPENAI_ENDPOINT = os.getenv("AZURE_OPENAI_ENDPOINT", "")
AZURE_OPENAI_KEY = os.getenv("AZURE_OPENAI_KEY", "")
AZURE_OPENAI_DEPLOYMENT = os.getenv("AZURE_OPENAI_DEPLOYMENT", "gpt-4-1-nano")
AZURE_OPENAI_API_VERSION = os.getenv("AZURE_OPENAI_API_VERSION", "2024-10-21")

POLL_SECONDS = int(os.getenv("POLL_SECONDS", "30"))
INCIDENT_COOLDOWN_SECONDS = int(os.getenv("INCIDENT_COOLDOWN_SECONDS", "120"))

GITOPS_REPOSITORY = os.getenv("GITOPS_REPOSITORY", "aks-gitops-sample-app")
INCIDENT_DEPLOYMENT_FILE = os.getenv("INCIDENT_DEPLOYMENT_FILE", "k8s/incident/deployment.yaml")
INCIDENT_SERVICE_FILE = os.getenv("INCIDENT_SERVICE_FILE", "k8s/incident/service.yaml")
EXPECTED_INCIDENT_IMAGE = os.getenv("EXPECTED_INCIDENT_IMAGE", "nginx:1.27-alpine")
EXPECTED_INCIDENT_APP_LABEL = os.getenv("EXPECTED_INCIDENT_APP_LABEL", "incident-demo")


app = FastAPI(title="AKS AIOps Controller", version="0.3.1")

last_incident_signature: Optional[str] = None
last_incident_time: float = 0
latest_report: Dict[str, Any] = {
    "status": "starting",
    "message": "AIOps controller is starting.",
    "updated_at": datetime.now(timezone.utc).isoformat(),
}


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def load_kube() -> None:
    try:
        config.load_incluster_config()
    except Exception:
        config.load_kube_config()


def kube_clients():
    return (
        client.CoreV1Api(),
        client.AppsV1Api(),
        client.CustomObjectsApi(),
    )


def pod_summary(pod: client.V1Pod) -> Dict[str, Any]:
    container_states = []

    statuses = pod.status.container_statuses or []
    for status in statuses:
        state = status.state
        waiting_reason = None
        waiting_message = None

        if state and state.waiting:
            waiting_reason = state.waiting.reason
            waiting_message = state.waiting.message

        container_states.append(
            {
                "name": status.name,
                "ready": status.ready,
                "restart_count": status.restart_count,
                "image": status.image,
                "waiting_reason": waiting_reason,
                "waiting_message": waiting_message,
            }
        )

    return {
        "name": pod.metadata.name,
        "namespace": pod.metadata.namespace,
        "labels": pod.metadata.labels or {},
        "phase": pod.status.phase,
        "pod_ip": pod.status.pod_ip,
        "node_name": pod.spec.node_name,
        "containers": container_states,
    }


def deployment_summary(dep: client.V1Deployment) -> Dict[str, Any]:
    containers = []
    for c in dep.spec.template.spec.containers:
        containers.append(
            {
                "name": c.name,
                "image": c.image,
                "ports": [p.container_port for p in (c.ports or [])],
            }
        )

    return {
        "name": dep.metadata.name,
        "namespace": dep.metadata.namespace,
        "replicas": dep.spec.replicas,
        "available_replicas": dep.status.available_replicas,
        "selector": dep.spec.selector.match_labels or {},
        "template_labels": dep.spec.template.metadata.labels or {},
        "containers": containers,
    }


def service_summary(svc: client.V1Service) -> Dict[str, Any]:
    ports = []
    for p in svc.spec.ports or []:
        ports.append(
            {
                "name": p.name,
                "port": p.port,
                "targetPort": p.target_port,
                "protocol": p.protocol,
            }
        )

    return {
        "name": svc.metadata.name,
        "namespace": svc.metadata.namespace,
        "type": svc.spec.type,
        "selector": svc.spec.selector or {},
        "ports": ports,
    }


def endpoints_summary(ep: client.V1Endpoints) -> Dict[str, Any]:
    addresses = []
    not_ready = []

    for subset in ep.subsets or []:
        for addr in subset.addresses or []:
            addresses.append(addr.ip)
        for addr in subset.not_ready_addresses or []:
            not_ready.append(addr.ip)

    return {
        "name": ep.metadata.name,
        "namespace": ep.metadata.namespace,
        "ready_addresses": addresses,
        "not_ready_addresses": not_ready,
        "ready_count": len(addresses),
        "not_ready_count": len(not_ready),
    }


def event_summary(event: client.CoreV1Event) -> Dict[str, Any]:
    return {
        "type": event.type,
        "reason": event.reason,
        "message": event.message,
        "involved_object": {
            "kind": event.involved_object.kind,
            "name": event.involved_object.name,
            "namespace": event.involved_object.namespace,
        },
        "last_timestamp": str(event.last_timestamp or event.event_time or event.metadata.creation_timestamp),
    }


def route_summary(route: Dict[str, Any]) -> Dict[str, Any]:
    spec = route.get("spec", {})
    rules = spec.get("rules", [])

    compact_rules = []
    for rule in rules:
        backends = []
        for backend in rule.get("backendRefs", []):
            backends.append(
                {
                    "name": backend.get("name"),
                    "port": backend.get("port"),
                    "weight": backend.get("weight"),
                }
            )
        compact_rules.append({"backendRefs": backends})

    return {
        "name": route.get("metadata", {}).get("name"),
        "namespace": route.get("metadata", {}).get("namespace"),
        "parentRefs": spec.get("parentRefs", []),
        "rules": compact_rules,
    }


def labels_match(selector: Dict[str, str], labels: Dict[str, str]) -> bool:
    if not selector:
        return False
    for key, value in selector.items():
        if labels.get(key) != value:
            return False
    return True


def detect_incident(evidence: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    image_pull_reasons = {"ImagePullBackOff", "ErrImagePull", "BackOff"}

    for pod in evidence["pods"]:
        for container in pod.get("containers", []):
            reason = container.get("waiting_reason")
            if reason in image_pull_reasons:
                image = container.get("image") or "unknown"
                return {
                    "incident_type": "image_pull_failure",
                    "affected_resource": f"Pod/{pod['name']}",
                    "symptom": f"Container {container['name']} is waiting with reason {reason}.",
                    "signature": f"image_pull_failure:{pod['name']}:{container['name']}:{reason}:{image}",
                    "deterministic_fix": {
                        "repository": GITOPS_REPOSITORY,
                        "file": INCIDENT_DEPLOYMENT_FILE,
                        "field": "spec.template.spec.containers[0].image",
                        "current_value": image,
                        "expected_value": EXPECTED_INCIDENT_IMAGE,
                    },
                }

    pods = evidence["pods"]
    for svc in evidence["services"]:
        selector = svc.get("selector", {})
        if not selector:
            continue

        ep = next((e for e in evidence["endpoints"] if e["name"] == svc["name"]), None)
        if not ep:
            continue

        matching_pods = [
            pod for pod in pods
            if labels_match(selector, pod.get("labels", {}))
        ]

        if ep.get("ready_count", 0) == 0 and len(matching_pods) == 0 and len(pods) > 0:
            current_app = selector.get("app", json.dumps(selector, sort_keys=True))
            return {
                "incident_type": "service_empty_endpoints",
                "affected_resource": f"Service/{svc['name']}",
                "symptom": "Service has zero ready endpoints and its selector does not match any running pods.",
                "signature": f"service_empty_endpoints:{svc['name']}:{json.dumps(selector, sort_keys=True)}",
                "deterministic_fix": {
                    "repository": GITOPS_REPOSITORY,
                    "file": INCIDENT_SERVICE_FILE,
                    "field": "spec.selector.app",
                    "current_value": current_app,
                    "expected_value": EXPECTED_INCIDENT_APP_LABEL,
                },
            }

    return None


def collect_evidence() -> Dict[str, Any]:
    v1, apps, custom = kube_clients()

    pods = v1.list_namespaced_pod(WATCH_NAMESPACE).items
    deployments = apps.list_namespaced_deployment(WATCH_NAMESPACE).items
    services = v1.list_namespaced_service(WATCH_NAMESPACE).items
    endpoints = v1.list_namespaced_endpoints(WATCH_NAMESPACE).items

    events = v1.list_namespaced_event(WATCH_NAMESPACE).items
    warning_events = [
        event_summary(e)
        for e in events
        if e.type == "Warning"
    ][-20:]

    try:
        httproutes_raw = custom.list_namespaced_custom_object(
            group="gateway.networking.k8s.io",
            version="v1",
            namespace=WATCH_NAMESPACE,
            plural="httproutes",
        )
        httproutes = [
            route_summary(item)
            for item in httproutes_raw.get("items", [])
        ]
    except ApiException:
        httproutes = []

    return {
        "cluster_context": {
            "watch_namespace": WATCH_NAMESPACE,
            "aiops_namespace": AIOPS_NAMESPACE,
            "collected_at": now_iso(),
        },
        "pods": [pod_summary(p) for p in pods],
        "deployments": [deployment_summary(d) for d in deployments],
        "services": [service_summary(s) for s in services],
        "endpoints": [endpoints_summary(e) for e in endpoints],
        "events": warning_events,
        "httproutes": httproutes,
        "gitops_repository": {
            "name": GITOPS_REPOSITORY,
            "known_paths": [
                INCIDENT_DEPLOYMENT_FILE,
                INCIDENT_SERVICE_FILE,
                "k8s/incident/httproute.yaml",
            ],
        },
    }


def build_patch_recommendation(incident: Dict[str, Any], ai_report: Dict[str, Any]) -> Dict[str, Any]:
    fix = ai_report.get("fix_location") or incident.get("deterministic_fix") or {}
    incident_type = ai_report.get("incident_type") or incident.get("incident_type")

    file_path = fix.get("file", "unknown")
    field = fix.get("field", "unknown")
    current_value = fix.get("current_value", "unknown")
    expected_value = fix.get("expected_value", "unknown")

    if isinstance(current_value, dict):
        current_value_for_text = current_value.get("app", json.dumps(current_value, sort_keys=True))
    else:
        current_value_for_text = str(current_value)

    if isinstance(expected_value, dict):
        expected_value_for_text = expected_value.get("app", json.dumps(expected_value, sort_keys=True))
    else:
        expected_value_for_text = str(expected_value)

    if incident_type == "service_empty_endpoints":
        diff = f"""--- a/{INCIDENT_SERVICE_FILE}
+++ b/{INCIDENT_SERVICE_FILE}
@@
 spec:
   type: ClusterIP
   selector:
-    app: {current_value_for_text}
+    app: {expected_value_for_text}
   ports:
     - name: http
       port: 80
       targetPort: 80
"""
        apply_hint = f"Update {INCIDENT_SERVICE_FILE} so spec.selector.app is {expected_value_for_text}."

    elif incident_type == "image_pull_failure":
        diff = f"""--- a/{INCIDENT_DEPLOYMENT_FILE}
+++ b/{INCIDENT_DEPLOYMENT_FILE}
@@
       containers:
         - name: nginx
-          image: {current_value_for_text}
+          image: {expected_value_for_text}
           ports:
             - name: http
               containerPort: 80
"""
        apply_hint = f"Update {INCIDENT_DEPLOYMENT_FILE} so spec.template.spec.containers[0].image is {expected_value_for_text}."

    else:
        diff = ""
        apply_hint = "No deterministic patch recommendation is available for this incident type."

    return {
        "format": "unified_diff",
        "repository": GITOPS_REPOSITORY,
        "file": file_path,
        "field": field,
        "current_value": current_value,
        "expected_value": expected_value,
        "diff": diff,
        "apply_mode": "manual_gitops_only",
        "human_review_required": True,
        "safe_next_step": apply_hint,
        "direct_cluster_changes": "not_performed",
    }


def analyze_with_ai(incident: Dict[str, Any], evidence: Dict[str, Any]) -> Dict[str, Any]:
    deterministic_fix = incident.get("deterministic_fix", {})

    if not AZURE_OPENAI_ENDPOINT or not AZURE_OPENAI_KEY:
        report = {
            "incident_type": incident["incident_type"],
            "affected_resource": incident["affected_resource"],
            "symptom": incident["symptom"],
            "root_cause": "Azure OpenAI environment variables are not configured.",
            "fix_location": deterministic_fix or {
                "repository": GITOPS_REPOSITORY,
                "file": "unknown",
                "field": "unknown",
                "current_value": "unknown",
                "expected_value": "unknown",
            },
            "evidence": ["A Kubernetes incident was detected, but AI analysis could not run."],
            "recommended_safe_next_steps": [
                "Create the aiops-openai-secret in the aiops-system namespace.",
                "Restart the aiops-controller deployment.",
            ],
            "confidence": "low",
        }
        report["patch_recommendation"] = build_patch_recommendation(incident, report)
        report["pull_request_recommendation"] = create_pr_from_report(report)
        return report

    aoai = AzureOpenAI(
        azure_endpoint=AZURE_OPENAI_ENDPOINT,
        api_key=AZURE_OPENAI_KEY,
        api_version=AZURE_OPENAI_API_VERSION,
    )

    system_prompt = """
You are an AKS GitOps AIOps incident analyzer.

Use only the evidence provided.
Do not invent files, commands, resources, namespaces, or values.
Do not recommend direct kubectl patching for application fixes.
Recommend GitOps-safe fixes only.

Return valid compact JSON only with this exact shape:
{
  "incident_type": "...",
  "affected_resource": "...",
  "symptom": "...",
  "root_cause": "...",
  "fix_location": {
    "repository": "aks-gitops-sample-app",
    "file": "...",
    "field": "...",
    "current_value": "...",
    "expected_value": "..."
  },
  "evidence": [],
  "recommended_safe_next_steps": [],
  "patch_intent": {
    "summary": "...",
    "human_review_required": true,
    "apply_mode": "manual_gitops_only"
  },
  "confidence": "high|medium|low"
}

For service selector incidents, the fix file should be k8s/incident/service.yaml.
For image pull incidents, the fix file should be k8s/incident/deployment.yaml.
Do not return kubectl patch commands.
"""

    user_payload = {
        "detected_incident": incident,
        "deterministic_fix_hint": deterministic_fix,
        "evidence": evidence,
    }

    response = aoai.chat.completions.create(
        model=AZURE_OPENAI_DEPLOYMENT,
        messages=[
            {"role": "system", "content": system_prompt.strip()},
            {"role": "user", "content": json.dumps(user_payload, separators=(",", ":"))},
        ],
        temperature=0,
        max_tokens=900,
    )

    content = response.choices[0].message.content or "{}"

    try:
        report = json.loads(content)
    except json.JSONDecodeError:
        report = {
            "incident_type": incident["incident_type"],
            "affected_resource": incident["affected_resource"],
            "symptom": incident["symptom"],
            "root_cause": "AI returned non-JSON output.",
            "fix_location": deterministic_fix or {
                "repository": GITOPS_REPOSITORY,
                "file": "unknown",
                "field": "unknown",
                "current_value": "unknown",
                "expected_value": "unknown",
            },
            "evidence": [content[:1000]],
            "recommended_safe_next_steps": [
                "Review the raw AI output.",
                "Retry analysis after checking the controller prompt and token limit.",
            ],
            "confidence": "low",
        }

    if not report.get("fix_location") and deterministic_fix:
        report["fix_location"] = deterministic_fix

    report["patch_recommendation"] = build_patch_recommendation(incident, report)
    report["pull_request_recommendation"] = create_pr_from_report(report)
    report["human_review_required"] = True
    report["apply_mode"] = "manual_gitops_only"

    return report


def write_report_configmap(report: Dict[str, Any]) -> None:
    v1, _, _ = kube_clients()

    data = {
        "report.json": json.dumps(report, indent=2),
        "updated_at": now_iso(),
    }

    body = client.V1ConfigMap(
        metadata=client.V1ObjectMeta(
            name=REPORT_CONFIGMAP,
            namespace=AIOPS_NAMESPACE,
            labels={"app": "aiops-controller"},
        ),
        data=data,
    )

    try:
        v1.replace_namespaced_config_map(REPORT_CONFIGMAP, AIOPS_NAMESPACE, body)
    except ApiException as e:
        if e.status == 404:
            v1.create_namespaced_config_map(AIOPS_NAMESPACE, body)
        else:
            raise


async def controller_loop() -> None:
    global last_incident_signature, last_incident_time, latest_report

    while True:
        try:
            evidence = collect_evidence()
            incident = detect_incident(evidence)

            if not incident:
                latest_report = {
                    "status": "healthy",
                    "message": "No supported incident detected.",
                    "watch_namespace": WATCH_NAMESPACE,
                    "updated_at": now_iso(),
                    "controller_version": "0.3.1",
                    "patch_recommendation": None,
                    "pull_request_recommendation": None,
                }
                write_report_configmap(latest_report)
                await asyncio.sleep(POLL_SECONDS)
                continue

            current_time = time.time()
            signature = incident["signature"]

            if (
                signature == last_incident_signature
                and current_time - last_incident_time < INCIDENT_COOLDOWN_SECONDS
            ):
                await asyncio.sleep(POLL_SECONDS)
                continue

            last_incident_signature = signature
            last_incident_time = current_time

            report = analyze_with_ai(incident, evidence)
            report["status"] = "incident_detected"
            report["updated_at"] = now_iso()
            report["controller_version"] = "0.3.1"
            report["controller_notes"] = {
                "direct_cluster_changes": "not_performed",
                "remediation_mode": "recommend_patch_only_gitops_safe",
                "cooldown_seconds": INCIDENT_COOLDOWN_SECONDS,
            }

            latest_report = report
            write_report_configmap(report)

        except Exception as exc:
            latest_report = {
                "status": "controller_error",
                "message": str(exc),
                "updated_at": now_iso(),
                "controller_version": "0.3.1",
            }

        await asyncio.sleep(POLL_SECONDS)


@app.on_event("startup")
async def startup_event() -> None:
    load_kube()
    asyncio.create_task(controller_loop())


@app.get("/healthz")
def healthz():
    return {"status": "ok", "updated_at": now_iso(), "version": "0.3.1"}


@app.get("/api/report")
def api_report():
    return JSONResponse(latest_report)


@app.get("/aiops", response_class=HTMLResponse)
def aiops_dashboard():
    report_json = json.dumps(latest_report, indent=2)

    root_cause = latest_report.get("root_cause", latest_report.get("message", "No report yet."))
    status = latest_report.get("status", "unknown")
    incident_type = latest_report.get("incident_type", "none")
    affected = latest_report.get("affected_resource", "none")
    confidence = latest_report.get("confidence", "n/a")

    patch = latest_report.get("patch_recommendation") or {}
    patch_diff = patch.get("diff", "")
    patch_file = patch.get("file", "n/a")
    patch_mode = patch.get("apply_mode", "n/a")
    human_review = patch.get("human_review_required", latest_report.get("human_review_required", "n/a"))

    pr = latest_report.get("pull_request_recommendation") or {}
    pr_status = pr.get("status", "n/a")
    pr_url = pr.get("url", "")
    pr_branch = pr.get("branch", "n/a")
    pr_reason = pr.get("reason", "")

    html_doc = f"""
<!doctype html>
<html>
<head>
  <title>AKS AIOps Patch Recommendation</title>
  <style>
    body {{
      font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      margin: 40px;
      background: #0f172a;
      color: #e5e7eb;
    }}
    .card {{
      background: #111827;
      border: 1px solid #374151;
      border-radius: 14px;
      padding: 24px;
      max-width: 1200px;
    }}
    .badge {{
      display: inline-block;
      padding: 6px 10px;
      border-radius: 999px;
      background: #1d4ed8;
      color: white;
      font-size: 13px;
    }}
    .warning {{
      padding: 12px;
      border-radius: 10px;
      background: #451a03;
      border: 1px solid #f97316;
      color: #fed7aa;
      margin: 16px 0;
    }}
    pre {{
      white-space: pre-wrap;
      background: #020617;
      padding: 18px;
      border-radius: 10px;
      overflow-x: auto;
      border: 1px solid #334155;
    }}
    h1, h2 {{
      margin-top: 0;
    }}
    .muted {{
      color: #9ca3af;
    }}
  </style>
</head>
<body>
  <div class="card">
    <h1>AKS AIOps Patch Recommendation</h1>
    <p class="badge">{html.escape(str(status))}</p>

    <h2>Summary</h2>
    <p><strong>Incident type:</strong> {html.escape(str(incident_type))}</p>
    <p><strong>Affected resource:</strong> {html.escape(str(affected))}</p>
    <p><strong>Root cause:</strong> {html.escape(str(root_cause))}</p>
    <p><strong>Confidence:</strong> {html.escape(str(confidence))}</p>

    <div class="warning">
      Human review is required. This controller does not patch Kubernetes resources and does not commit to Git.
      Apply recommendations only through your GitOps workflow.
    </div>

    <h2>Patch recommendation</h2>
    <p><strong>File:</strong> {html.escape(str(patch_file))}</p>
    <p><strong>Apply mode:</strong> {html.escape(str(patch_mode))}</p>
    <p><strong>Human review required:</strong> {html.escape(str(human_review))}</p>
    <pre>{html.escape(str(patch_diff or "No patch recommendation is available."))}</pre>

    <h2>Pull request recommendation</h2>
    <p><strong>Status:</strong> {html.escape(str(pr_status))}</p>
    <p><strong>Branch:</strong> {html.escape(str(pr_branch))}</p>
    <p><strong>Reason:</strong> {html.escape(str(pr_reason))}</p>
    <p><strong>URL:</strong> {f'<a href="{html.escape(str(pr_url))}" target="_blank" style="color:#93c5fd">{html.escape(str(pr_url))}</a>' if pr_url else 'n/a'}</p>
    <p><strong>Auto merge:</strong> not performed</p>

    <h2>Raw report</h2>
    <pre>{html.escape(report_json)}</pre>

    <p class="muted">
      GitOps-safe mode: recommend only. No direct cluster changes are performed.
    </p>
  </div>
</body>
</html>
"""
    return HTMLResponse(html_doc)
