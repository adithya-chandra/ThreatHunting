# a1.py
import os
import re
import json
import uuid
import time
import base64
import logging
from typing import Dict, List, Any, Optional, Tuple

import requests
import chainlit as cl
from dotenv import load_dotenv

# Optional PDF parsing
from PyPDF2 import PdfReader

import boto3

load_dotenv()

AWS_REGION = os.getenv("AWS_REGION", "us-east-1")
MODEL_ID = os.getenv("BEDROCK_MODEL_ID", "us.anthropic.claude-3-5-sonnet-v2:0")
VT_API_KEY = os.getenv("VT_API_KEY")  # required for VT enrichment
WORKSPACE_DIR = os.getenv("WORKSPACE_DIR", "./workspace")

os.makedirs(WORKSPACE_DIR, exist_ok=True)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("a1")

#claude
def bedrock_client():
    return boto3.client("bedrock-runtime", region_name=AWS_REGION)

def call_claude(system: str, user: str, temperature: float = 0.2, max_tokens: int = 2000) -> str:
    """
    Calls Amazon Bedrock Anthropic Claude with messages format.
    """
    brt = bedrock_client()
    body = {
        "anthropic_version": "bedrock-2023-05-31",
        "max_tokens": max_tokens,
        "temperature": temperature,
        "system": system,
        "messages": [
            {"role": "user", "content": [{"type": "text", "text": user}]}
        ],
    }

    resp = brt.invoke_model(
        modelId=MODEL_ID,
        body=json.dumps(body).encode("utf-8"),
        accept="application/json",
        contentType="application/json",
    )
    payload = json.loads(resp["body"].read())
    # Anthropic content comes as a list of blocks
    out = []
    for blk in payload.get("content", []):
        if blk.get("type") == "text":
            out.append(blk.get("text", ""))
    return "\n".join(out).strip()

# IOC regex 

IOC_PATTERNS = {
    "ipv4": re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"),
    "domain": re.compile(r"\b(?!(?:\d{1,3}\.){3}\d{1,3})(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63}\b"),
    "sha256": re.compile(r"\b[a-fA-F0-9]{64}\b"),
    "sha1": re.compile(r"\b[a-fA-F0-9]{40}\b"),
    "md5": re.compile(r"\b[a-fA-F0-9]{32}\b"),
    "url": re.compile(r"\bhttps?://[^\s)\"'<>]+", re.IGNORECASE),
}

def extract_iocs_from_text(text: str) -> Dict[str, List[str]]:
    found = {k: sorted(set(p.findall(text))) for k, p in IOC_PATTERNS.items()}
    return {k: v for k, v in found.items() if v}

def extract_iocs_from_pdf(file_path: str) -> Dict[str, List[str]]:
    reader = PdfReader(file_path)
    full_text = []
    for page in reader.pages:
        try:
            full_text.append(page.extract_text() or "")
        except Exception:
            pass
    return extract_iocs_from_text("\n".join(full_text))

def extract_iocs_from_json(file_path: str) -> Dict[str, List[str]]:
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            obj = json.load(f)
        txt = json.dumps(obj)
        return extract_iocs_from_text(txt)
    except Exception:
        return {}

# VT Code
VT_BASE = "https://www.virustotal.com/api/v3"
HEADERS = {"x-apikey": VT_API_KEY}

_HASH_RXES = {
    "md5": re.compile(r"^[A-Fa-f0-9]{32}$"),
    "sha1": re.compile(r"^[A-Fa-f0-9]{40}$"),
    "sha256": re.compile(r"^[A-Fa-f0-9]{64}$"),
}


def _safe_get(url: str, params: dict | None = None, timeout: int = 30):
    """Thin wrapper (status_code, json_or_text)."""
    resp = requests.get(url, headers=HEADERS, params=params or {}, timeout=timeout)
    text = resp.text or ""
    try:
        data = resp.json()
    except Exception:
        data = text
    return resp.status_code, data

def _is_hex_hash(s: str) -> bool:
    s = (s or "").strip().strip('"').strip("'")
    return any(rx.match(s) for rx in _HASH_RXES.values())

def _normalize_hash(s: str) -> str:
    return (s or "").strip().strip('"').strip("'").lower()

def _http_get(path: str, params: Dict[str, Any] | None = None, timeout: int = 30) -> Tuple[int, Any]:
    url = f"{VT_BASE}{path}"
    r = requests.get(url, headers=HEADERS, params=params or {}, timeout=timeout)
    try:
        data = r.json()
    except Exception:
        data = r.text
    return r.status_code, data

def _resolve_file_id_via_search(hv: str) -> str | None:
    # Fallback: /search?query=<hash> → first item id (usually sha256)
    sc, data = _http_get("/search", params={"query": hv})
    if sc != 200 or not isinstance(data, dict):
        return None
    items = data.get("data") or []
    if isinstance(items, list) and items:
        first = items[0]
        if isinstance(first, dict):
            return first.get("id")
    return None

def _fetch_relationship_ids(file_id: str, rel_name: str, limit: int = 40) -> List[str]:
    sc, data = _http_get(f"/files/{file_id}/relationships/{rel_name}", params={"limit": limit})
    if sc != 200 or not isinstance(data, dict):
        return []
    out = []
    for it in data.get("data", []) or []:
        if isinstance(it, dict) and it.get("id"):
            out.append(it["id"])
    return out

def enrich_hash(hash_value: str) -> dict:
    """
    try check
    """
    hv = _normalize_hash(hash_value)
    if not _is_hex_hash(hv):
        return {"hash": hash_value, "status": 400, "error": "invalid_hash_format"}

    #direct lookup
    status, data = _http_get(f"/files/{hv}")
    file_id = None
    if status == 200 and isinstance(data, dict):
        file_id = (data.get("data") or {}).get("id")
    elif status == 404:
        #fix for “404 for any hash” when MD5/SHA1 given
        resolved = _resolve_file_id_via_search(hv)
        if not resolved:
            return {"hash": hash_value, "status": 404, "error": "not_found", "raw": data}
        status2, data2 = _http_get(f"/files/{resolved}")
        if status2 != 200:
            return {"hash": hash_value, "status": status2, "error": "not_found_after_search", "raw": data2}
        file_id = resolved
        data = data2
        status = status2
    else:
        #othererrors (401/403/)
        return {"hash": hash_value, "status": status, "error": f"http_{status}", "raw": data}

    if not file_id:
        return {"hash": hash_value, "status": 500, "error": "missing_file_id", "raw": data}

    #lists of IDs
    result = {
        "hash": hash_value,
        "status": 200,
        "file_id": file_id,
        "relationships": {
            "names": _fetch_relationship_ids(file_id, "names"),
            "contacted_domains": _fetch_relationship_ids(file_id, "contacted_domains"),
            "contacted_ips": _fetch_relationship_ids(file_id, "contacted_ips"),
            "execution_parents": _fetch_relationship_ids(file_id, "execution_parents"),
        },
        #"raw": data,  
    }
    return result




def enrich_ip(ip_address: str) -> dict:
    """
    Enrich an IP address and return the 'communicating_files' and 'referrer_files'
    """
    rels = "communicating_files,referrer_files,related_threat_actors"
    url = f"{VT_BASE}/ip_addresses/{ip_address}"
    params = {"relationships": rels}

    status, data = _safe_get(url, params=params)
    result = {"ip": ip_address, "status": status}

    if status == 404:
        result["error"] = "not_found"
        result["raw"] = data
        return result
    if status in (401, 403):
        result["error"] = "auth_forbidden"
        result["raw"] = data
        return result
    if status != 200:
        result["error"] = f"http_{status}"
        result["raw"] = data
        return result

    data_obj = data.get("data", {}) if isinstance(data, dict) else {}
    rels_obj = data_obj.get("relationships", {}) if isinstance(data_obj, dict) else {}

    def _extract_ids(rel_name: str):
        ent = rels_obj.get(rel_name, {}) or {}
        d = ent.get("data", [])
        if isinstance(d, dict):
            return [d.get("id")] if d.get("id") else []
        if isinstance(d, list):
            return [item.get("id") for item in d if isinstance(item, dict) and item.get("id")]
        return []

    result["communicating_files"] = _extract_ids("communicating_files")
    result["APT Group"] = _extract_ids("related_threat_actors")
    result["referrer_files"] = _extract_ids("referrer_files")
    #result["raw"] = data
    return result




#prompts
SYS_THREAT_INTEL = """You are a Threat Intelligence analyst. Be precise and structured.
When asked for APT IOCs, return curated indicators with types and brief context.
When asked for MITRE ATT&CK technique (e.g., T1547), return: Name, Tactic(s), Summary, Common procedures, Detection ideas, References (if known).
If unsure, say so; avoid fabrications.
"""

def prompt_for_apt_iocs(apt_name: str) -> str:
    return f"""Provide a concise, structured list of current, well-known IOCs for {apt_name}.
Group by type (domains, IPs, file hashes, filenames, mutexes, reg keys, tools), and add a one-line note if an IOC is deprecated or noisy.
Format as bullet points."""

def prompt_for_mitre(tech_id: str) -> str:
    return f"""Give a clean overview for MITRE ATT&CK technique {tech_id}.
Include: Name, ID, Tactic(s), Summary, Detection opportunities, Data sources, Common sub-techniques, and brief hunting queries (vendor-neutral)."""


#Session
def session_file(session_id: str) -> str:
    return os.path.join(WORKSPACE_DIR, f"session_{session_id}.json")

def save_session_payload(session_id: str, payload: Dict[str, Any]) -> None:
    path = session_file(session_id)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)


# Chainlit app
@cl.on_chat_start
async def on_chat_start():
    sid = str(uuid.uuid4())[:8]
    cl.user_session.set("sid", sid)
    await cl.Message(
        content=(
            "**Threat Intel Enrichment Agent (a1)**\n\n"
            "**What I can do:**\n"
            "• Get IOCs for APT groups (e.g., `IOC APT28`)\n"
            "• MITRE ATT&CK details (e.g., `MITRE T1547`)\n"
            "• VirusTotal enrichment: IP or Hash\n\n"
            f"**Session ID:** `{sid}` (used by a2.py to pull results)\n\n"
        )
    ).send()

@cl.on_message
async def on_message(message: cl.Message):
    text = (message.content or "").strip()
    files = message.elements or []

    sid = cl.user_session.get("sid")
    results: Dict[str, Any] = {
        "session_id": sid,
        "timestamp": int(time.time()),
        "inputs": {"text": text},
        "extracted_iocs": {},
        "intel": {},
        "vt": {},
    }

    # 1) If files present, parse for IOCs?check logic
    aggregated_iocs: Dict[str, List[str]] = {}
    for f in files:
        if not hasattr(f, "path"):
            continue
        try:
            if f.mime and "pdf" in f.mime.lower():
                iocs = extract_iocs_from_pdf(f.path)
            elif f.mime and "json" in f.mime.lower():
                iocs = extract_iocs_from_json(f.path)
            else:
                # fallback plain text read
                with open(f.path, "rb") as fd:
                    raw = fd.read().decode(errors="ignore")
                iocs = extract_iocs_from_text(raw)
            # merge
            for k, vals in iocs.items():
                aggregated_iocs.setdefault(k, [])
                aggregated_iocs[k].extend(vals)
        except Exception as e:
            await cl.Message(content=f"⚠️ Failed to parse `{getattr(f, 'name', 'file')}`: {e}").send()

    # dedup
    for k in list(aggregated_iocs.keys()):
        aggregated_iocs[k] = sorted(set(aggregated_iocs[k]))
    if aggregated_iocs:
        results["extracted_iocs"] = aggregated_iocs
        await cl.Message(content="📎 Extracted IOCs from file(s):\n" + json.dumps(aggregated_iocs, indent=2)).send()

    # 2) Parse intent from text
    intent = None
    m = re.match(r"(?i)^\s*(IOC)\s+(.+)$", text)
    if m:
        intent = ("ioc_group", m.group(2).strip())
    m = re.match(r"(?i)^\s*(MITRE)\s+([tT]\d{4}(?:\.\d{3})?)\s*$", text)
    if m:
        intent = intent or ("mitre", m.group(2).upper())
    m = re.match(r"(?i)^\s*ENRICH\s+IP\s+([0-9\.]+)\s*$", text)
    if m:
        intent = intent or ("vt_ip", m.group(1))
    m = re.match(r"(?i)^\s*ENRICH\s+HASH\s+([A-Fa-f0-9]{32,64})\s*$", text)
    if m:
        intent = intent or ("vt_hash", m.group(1))

   
    if not intent:
        # detect if it's a plain IP or hash
        ip_match = IOC_PATTERNS["ipv4"].search(text)
        hash_match = IOC_PATTERNS["sha256"].search(text) or IOC_PATTERNS["sha1"].search(text) or IOC_PATTERNS["md5"].search(text)
        mitre_match = re.search(r"(?i)\b(T\d{4}(?:\.\d{3})?)\b", text)
        if ip_match:
            intent = ("vt_ip", ip_match.group(0))
        elif hash_match:
            intent = ("vt_hash", hash_match.group(0))
        elif mitre_match:
            intent = ("mitre", mitre_match.group(1).upper())
        elif text.lower().startswith("help me with the ioc") or text.lower().startswith("help me with ioc") or "apt" in text.lower():
            # extract a potential group name, fallback to whole text
            w = re.search(r"(?i)\b(apt\d{1,3}[a-z]?|sandworm|lazarus|turla|apt28|fancy bear|cozy bear|apt29)\b", text)
            intent = ("ioc_group", w.group(0)) if w else ("ioc_group", text)

    # 4) Execute intent
    try:
        if intent and intent[0] == "ioc_group":
            group = intent[1]
            await cl.Message(content=f"🔎 Fetching public IOC overview for **{group}**...").send()
            intel = call_claude(
                system=SYS_THREAT_INTEL,
                user=prompt_for_apt_iocs(group),
            )
            results["intel"]["apt_iocs"] = {"group": group, "content": intel}
            await cl.Message(content=intel).send()

        elif intent and intent[0] == "mitre":
            tech = intent[1]
            await cl.Message(content=f"🧭 Getting MITRE ATT&CK details for **{tech}**...").send()
            intel = call_claude(
                system=SYS_THREAT_INTEL,
                user=prompt_for_mitre(tech),
            )
            results["intel"]["mitre"] = {"technique": tech, "content": intel}
            await cl.Message(content=intel).send()

        elif intent and intent[0] == "vt_ip":
            ip = intent[1]
            await cl.Message(content=f"🌐 VT enrichment for IP **{ip}** (communicating_files, referrer_files)...").send()
            vt = enrich_ip(ip)
            results["vt"]["ip"] = vt
            await cl.Message(content="```json\n" + json.dumps(vt, indent=2) + "\n```").send()

        elif intent and intent[0] == "vt_hash":
            hv = intent[1]
            await cl.Message(content=f"🧬 VT enrichment for Hash **{hv}** (names, contacted-domains, contacted-ips, execution-parents)...").send()
            vt = enrich_hash(hv)
            results["vt"]["hash"] = vt
            await cl.Message(content="```json\n" + json.dumps(vt, indent=2) + "\n```").send()

        else:
            if not aggregated_iocs:
                await cl.Message(
                    content=(
                        "I can help with APT IOCs, MITRE details, and VT enrichment. "
                        "Try: `IOC APT28`, `MITRE T1547`, `ENRICH IP 8.8.8.8` etc"
                    )
                ).send()

    except Exception as e:
        await cl.Message(content=f"❌ Error: {e}").send()

    #Save current snapshot for a2.py
    try:
        # Merge extracted_iocs
        quick = aggregated_iocs.copy()
        if "ip" in results.get("vt", {}):
            # pull any hashes from relationships
            pass
        if "hash" in results.get("vt", {}):
            # pull any domains/ips from relationships for quick use
            rh = results["vt"]["hash"].get("relationships", {})
            if isinstance(rh.get("contacted_domains"), list):
                quick.setdefault("domain", [])
                quick["domain"].extend([d["id"] for d in rh["contacted_domains"] if isinstance(d, dict) and "id" in d])
            if isinstance(rh.get("contacted_ips"), list):
                quick.setdefault("ipv4", [])
                quick["ipv4"].extend([d["id"] for d in rh["contacted_ips"] if isinstance(d, dict) and "id" in d])
            #check:names are strings; might include paths/filenames
        for k in list(quick.keys()):
            quick[k] = sorted(set(quick[k]))
        results["quick_indicators"] = quick

        save_session_payload(sid, results)
        await cl.Message(content=f"💾 Saved snapshot for a2.py: `workspace/session_{sid}.json`").send()
    except Exception as e:
        await cl.Message(content=f"⚠️ Could not save session snapshot: {e}").send()
