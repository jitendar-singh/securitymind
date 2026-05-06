"""Multi-framework threat modeling orchestrator.

Runs each applicable Framework strategy via Gemini, merges per-framework results into
a single ThreatModelReport, and persists via MemoryManager.
"""

import json
import logging
import os
import re
from datetime import datetime
from typing import Any, Dict, List, Optional

from secmind.llm import generate_json
from secmind.memory import MemoryProxy
from secmind.memory_manager import MemoryManager

from . import report_generator
from .constants import DEFAULT_MODEL, GENERATION_TEMPERATURE, MAX_RETRIES
from .dfd_generator import DFDGenerator
from .frameworks import Framework, detect_frameworks, get_by_name
from .frameworks.base import FrameworkResult
from .models import ThreatModelReport, ThreatModelResult

logger = logging.getLogger(__name__)


def _build_report_filename(app_details: Dict[str, Any]) -> str:
    raw = (app_details or {}).get("name") or "Unknown App"
    name = re.sub(r"[\\/]", "-", str(raw)).strip()
    name = re.sub(r"[\x00-\x1f]", "", name)
    name = re.sub(r"\s+", " ", name)
    name = name[:80] or "Unknown App"
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    return f"Threat Model-{name}-{ts}.html"


def _resolve_frameworks(
    app_details: Dict[str, Any], frameworks_arg: str
) -> List[Framework]:
    arg = (frameworks_arg or "auto").strip().lower()
    if arg in ("", "auto", "all-applicable"):
        return detect_frameworks(app_details)
    if arg == "all":
        from .frameworks import ALL_FRAMEWORKS
        return list(ALL_FRAMEWORKS)
    names = [n for n in (s.strip() for s in arg.split(",")) if n]
    return get_by_name(names)


def _merge_recommendations(
    target: Dict[str, List[str]], addition: Dict[str, List[str]]
) -> None:
    for category, items in (addition or {}).items():
        if not items:
            continue
        existing = target.setdefault(category, [])
        for item in items:
            if item and item not in existing:
                existing.append(item)


def _dedupe_vulns(
    vulns: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    seen = set()
    out: List[Dict[str, Any]] = []
    for v in vulns:
        key = (v.get("vulnerability", "").strip().lower(), v.get("component", "").strip().lower())
        if key in seen:
            continue
        seen.add(key)
        v.setdefault("cwe_id", None)
        out.append(v)
    return out


def _populate_cross_references(threats: List[Dict[str, Any]]) -> None:
    """Populate cross_references by matching technique_ids that frameworks declared as overlapping."""
    by_technique: Dict[str, List[Dict[str, Any]]] = {}
    for t in threats:
        tid = (t.get("technique_id") or "").strip()
        if tid:
            by_technique.setdefault(tid, []).append(t)

    for t in threats:
        seeds = list(t.get("cross_references") or [])
        if not seeds:
            continue
        for seed in seeds:
            seed_id = seed.strip()
            for partner in by_technique.get(seed_id, []):
                if partner is t:
                    continue
                partner_xrefs = partner.setdefault("cross_references", [])
                own_id = (t.get("technique_id") or "").strip()
                if own_id and own_id not in partner_xrefs:
                    partner_xrefs.append(own_id)


def _aggregate_risk(framework_scores: Dict[str, int], threats: List[Dict[str, Any]]) -> int:
    if not framework_scores:
        return 0
    counts: Dict[str, int] = {fw: 0 for fw in framework_scores}
    for t in threats:
        fw = t.get("framework")
        if fw in counts:
            counts[fw] += 1
    weighted_sum = 0.0
    weight_total = 0.0
    for fw, score in framework_scores.items():
        # Each framework gets a base weight of 1, plus its threat count
        w = 1 + counts.get(fw, 0)
        weighted_sum += score * w
        weight_total += w
    if weight_total == 0:
        return 0
    return min(100, max(0, int(round(weighted_sum / weight_total))))


class ThreatModeler:
    """Multi-framework threat modeling orchestrator."""

    def __init__(self, model: str = DEFAULT_MODEL, memory_manager: Optional[MemoryManager] = None):
        self.model_name = model
        # MemoryProxy resolves to the current request user's manager on each
        # call, so this singleton-built ThreatModeler doesn't pin one user's
        # memory store.
        self.memory = memory_manager or MemoryProxy()
        logger.info("Initialized ThreatModeler with model: %s", self.model_name)

    def generate_threat_model(
        self,
        app_details: Dict[str, Any],
        frameworks_arg: str = "auto",
    ) -> ThreatModelResult:
        if not app_details:
            return {
                "status": "error",
                "message": "Application details cannot be empty.",
                "report": None,
            }

        frameworks = _resolve_frameworks(app_details, frameworks_arg)
        if not frameworks:
            return {
                "status": "error",
                "message": "No applicable frameworks found.",
                "report": None,
            }
        framework_names = [fw.name for fw in frameworks]

        cached = self.memory.get_threat_model(app_details, framework_names)
        if cached:
            return {
                "status": "success",
                "report": cached,
                "message": "Report retrieved from cache.",
            }

        try:
            dfd = DFDGenerator(app_details).generate_dfd()
        except Exception as exc:
            logger.warning("DFD generation failed (continuing without DFD): %s", exc)
            dfd = None

        per_framework: List[FrameworkResult] = []
        if len(frameworks) > 1:
            from concurrent.futures import ThreadPoolExecutor, as_completed
            with ThreadPoolExecutor(max_workers=len(frameworks)) as pool:
                futures = {pool.submit(self._run_framework, fw, app_details): fw for fw in frameworks}
                for future in as_completed(futures):
                    result = future.result()
                    if result is not None:
                        per_framework.append(result)
        else:
            for fw in frameworks:
                result = self._run_framework(fw, app_details)
                if result is not None:
                    per_framework.append(result)

        if not per_framework:
            return {
                "status": "error",
                "message": "All framework runs failed.",
                "report": None,
            }

        report = self._merge(per_framework, dfd)
        self.memory.add_threat_model(app_details, report, framework_names)

        return {"status": "success", "report": report, "message": None}

    def _run_framework(
        self, framework: Framework, app_details: Dict[str, Any]
    ) -> Optional[FrameworkResult]:
        try:
            prompt = framework.build_prompt(app_details)
            raw = self._generate_with_retry(prompt)
            if not raw:
                logger.error("Framework %s: empty response after retries", framework.name)
                return None
            return framework.parse_response(raw)
        except json.JSONDecodeError as e:
            logger.error("Framework %s: invalid JSON response: %s", framework.name, e)
            return None
        except Exception as e:
            logger.error("Framework %s: unexpected error: %s", framework.name, e, exc_info=True)
            return None

    def _current_model(self):
        """Read the model from the ADK agent (respects per-request Settings override)."""
        from .agent import threat_modeling_agent
        return getattr(threat_modeling_agent, "model", self.model_name)

    def _generate_with_retry(self, prompt: str, retries: int = MAX_RETRIES) -> Optional[str]:
        model = self._current_model()
        for attempt in range(retries):
            try:
                text = generate_json(
                    prompt, model, temperature=GENERATION_TEMPERATURE,
                )
                if text:
                    return text
                logger.warning("Attempt %d returned empty text", attempt + 1)
            except Exception as e:
                logger.warning("Attempt %d failed: %s", attempt + 1, e)
                if attempt == retries - 1:
                    raise
        return None

    def _merge(
        self,
        per_framework: List[FrameworkResult],
        dfd: Optional[str],
    ) -> ThreatModelReport:
        all_threats: List[Dict[str, Any]] = []
        all_vulns: List[Dict[str, Any]] = []
        recommendations: Dict[str, List[str]] = {}
        compliance: List[str] = []
        framework_scores: Dict[str, int] = {}
        framework_overviews: Dict[str, str] = {}

        for r in per_framework:
            fw = r["framework"]
            framework_scores[fw] = r.get("risk_score", 50)
            framework_overviews[fw] = r.get("overview", "")
            all_threats.extend(r.get("identified_threats", []) or [])
            all_vulns.extend(r.get("vulnerabilities", []) or [])
            _merge_recommendations(recommendations, r.get("recommendations") or {})
            for note in (r.get("compliance_notes") or []):
                if note and note not in compliance:
                    compliance.append(note)

        _populate_cross_references(all_threats)
        all_vulns = _dedupe_vulns(all_vulns)

        names = list(framework_scores.keys())
        agg = _aggregate_risk(framework_scores, all_threats)
        overview = (
            f"Threat model applies {len(names)} framework(s): {', '.join(names)}. "
            f"Aggregate risk: {agg}/100."
        )

        report: ThreatModelReport = {
            "overview": overview,
            "risk_score": agg,
            "framework_scores": framework_scores,
            "frameworks_applied": names,
            "framework_overviews": framework_overviews,
            "identified_threats": all_threats,
            "vulnerabilities": all_vulns,
            "recommendations": recommendations,
            "compliance_notes": compliance or None,
            "dfd": dfd,
        }
        return report


_threat_modeler: Optional[ThreatModeler] = None


def get_threat_modeler() -> ThreatModeler:
    global _threat_modeler
    if _threat_modeler is None:
        _threat_modeler = ThreatModeler()
    return _threat_modeler


def generate_threat_model_report(app_details: str, frameworks: str = "auto") -> str:
    """Generate a multi-framework threat model report.

    Args:
        app_details: JSON string with application details.
        frameworks: Comma-separated framework names (e.g. "stride,atlas") or "auto" for
            auto-detection. STRIDE is always included as the baseline. Other supported
            frameworks: ATLAS, OWASP-LLM, LINDDUN, ATT&CK.

    Returns:
        A status message — on success includes the report path.
    """
    try:
        app_details_dict = json.loads(app_details) if isinstance(app_details, str) else app_details

        modeler = get_threat_modeler()
        result = modeler.generate_threat_model(app_details_dict, frameworks_arg=frameworks)

        if result["status"] == "error":
            return f"Failed to generate threat model: {result['message']}"

        html_report = report_generator.generate_html_report(result["report"])
        from secmind.reports import user_reports_dir
        reports_dir = user_reports_dir()
        report_path = os.path.join(reports_dir, _build_report_filename(app_details_dict))
        with open(report_path, "w") as f:
            f.write(html_report)

        applied = ", ".join(result["report"].get("frameworks_applied", []))
        return f"Successfully generated threat model report ({applied}): {report_path}"

    except json.JSONDecodeError as e:
        logger.error("Invalid JSON in app_details: %s", e)
        return f"Error: Invalid JSON format: {e}"
    except Exception as e:
        logger.error("Error in generate_threat_model_report: %s", e, exc_info=True)
        return f"Error: {e}"
