# app.py
import os
import re
import json
import time
import uuid
import logging
from pytap import pytap
from typing import Any, Dict, List

import chainlit as cl
from dotenv import load_dotenv

#A1 utilities
from a1 import (
    IOC_PATTERNS,
    extract_iocs_from_pdf,
    extract_iocs_from_json,
    extract_iocs_from_text,
    enrich_ip,
    enrich_hash,
    call_claude as claude_a1,
    SYS_THREAT_INTEL,
    prompt_for_apt_iocs,
    prompt_for_mitre,
    save_session_payload,
)

#A2 utilities
from a2 import (
    run_alerts_and_save,
    load_session_json,
    flatten_iocs,
    build_queries_from_session,  # BUILD → style_template, returns quests and saves quests_<id>.json
)

load_dotenv()
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("app")

WORKSPACE_DIR = os.getenv("WORKSPACE_DIR", "./workspace")
os.makedirs(WORKSPACE_DIR, exist_ok=True)

HELP_A1 = (
    "🏹 **Threat Intel Enrichment (Mode: A1)**\n"
    "• Get IOCs for APT groups — `IOC APT28`\n"
    "• MITRE ATT&CK details — `MITRE T1547`\n"
    "• VirusTotal enrichment — `ENRICH IP 1.2.3.4` or `ENRICH HASH <hash>`\n"
    "• Snapshot auto-saved for A2\n"
)

HELP_A2 = (
    "🛠️ **Helix/Trellix Query Builder (Mode: A2)**\n"
    "• Load A1 session — `USE <session_id>` (or upload `session_*.json`)\n"
    "• View IOCs — `SHOW IOC`\n"
    "• Build Hunting questions — `BUILD` (saves `quests_<session_id>.json`)\n"
    "• Hunt for logs — `HUNT` (saves `quests_<session_id>.json`)\n"
    "• Alerts from Helix — `ALERT` [in progress*] (saves `session_<session_id>.json`)\n"
)

HELP_SHARED = "🔀 Switch mode: `MODE A1` or `MODE A2`"

def new_session_id() -> str:
    return str(uuid.uuid4())[:8]

def summarize_iocs(iocs: Dict[str, List[str]]) -> str:
    keys = [k for k, v in iocs.items() if v]
    total = sum(len(v) for v in iocs.values())
    return f"{total} indicators across: {', '.join(keys) if keys else '—'}"

def try_import_tap():
    try:
        from pytap import pytap
        return pytap
    except Exception:
        return None

# Chatlc
@cl.on_chat_start
async def on_chat_start():
    cl.user_session.set("mode", "A1")
    sid = new_session_id()
    cl.user_session.set("sid", sid)
    await cl.Message(
        content=(
            f"Session ID: `{sid}`\n\n{HELP_A1}\n\n{HELP_SHARED}"
        )
    ).send()

@cl.on_message
async def on_message(message: cl.Message):
    text = (message.content or "").strip()
    files = message.elements or []
    mode: str = cl.user_session.get("mode", "A1")
    sid: str = cl.user_session.get("sid")

    # Mode switch
    m_mode = re.match(r"(?i)^\s*MODE\s+(A1|A2)\s*$", text)
    if m_mode:
        mode = m_mode.group(1).upper()
        cl.user_session.set("mode", mode)
        help_msg = HELP_A1 if mode == "A1" else HELP_A2
        await cl.Message(content=f"✅ Switched to **{mode}**.\n\n{help_msg}\n\n{HELP_SHARED}").send()
        return

    if mode == "A1":
        await handle_mode_a1(message, text, files, sid)
    else:
        await handle_mode_a2(message, text, files)


# Mode A1: Enrichment

async def handle_mode_a1(message: cl.Message, text: str, files: List[Any], sid: str):
    results: Dict[str, Any] = {
        "session_id": sid,
        "timestamp": int(time.time()),
        "inputs": {"text": text},
        "extracted_iocs": {},
        "intel": {},
        "vt": {},
    }

    # File IOC extraction
    aggregated_iocs: Dict[str, List[str]] = {}
    for f in files:
        try:
            name = getattr(f, "name", "file")
            mime = (getattr(f, "mime", "") or "").lower()
            path = getattr(f, "path", None)
            if not path:
                continue

            if "pdf" in mime:
                iocs = extract_iocs_from_pdf(path)
            elif "json" in mime:
                iocs = extract_iocs_from_json(path)
            else:
                with open(path, "rb") as fd:
                    raw = fd.read().decode(errors="ignore")
                iocs = extract_iocs_from_text(raw)

            for k, vals in iocs.items():
                aggregated_iocs.setdefault(k, [])
                aggregated_iocs[k].extend(vals)
        except Exception as e:
            await cl.Message(content=f"⚠️ Failed to parse `{name}`: {e}").send()

    for k in list(aggregated_iocs.keys()):
        aggregated_iocs[k] = sorted(set(aggregated_iocs[k]))
    if aggregated_iocs:
        results["extracted_iocs"] = aggregated_iocs
        await cl.Message(content="📎 Extracted IOCs:\n```json\n" + json.dumps(aggregated_iocs, indent=2) + "\n```").send()


    intent = None
    m = re.match(r"(?i)^\s*IOC\s+(.+)$", text)
    if m: intent = ("ioc_group", m.group(1).strip())
    m = re.match(r"(?i)^\s*MITRE\s+([tT]\d{4}(?:\.\d{3})?)\s*$", text)
    if m and not intent: intent = ("mitre", m.group(1).upper())
    m = re.match(r"(?i)^\s*ENRICH\s+IP\s+([0-9\.]+)\s*$", text)
    if m and not intent: intent = ("vt_ip", m.group(1))
    m = re.match(r"(?i)^\s*ENRICH\s+HASH\s+([A-Fa-f0-9]{32,64})\s*$", text)
    if m and not intent: intent = ("vt_hash", m.group(1))

    if not intent and text:
        ip_match = IOC_PATTERNS["ipv4"].search(text)
        hash_match = (IOC_PATTERNS["sha256"].search(text) or IOC_PATTERNS["sha1"].search(text) or IOC_PATTERNS["md5"].search(text))
        mitre_match = re.search(r"(?i)\b(T\d{4}(?:\.\d{3})?)\b", text)
        if ip_match:
            intent = ("vt_ip", ip_match.group(0))
        elif hash_match:
            intent = ("vt_hash", hash_match.group(0))
        elif mitre_match:
            intent = ("mitre", mitre_match.group(1).upper())
        elif "apt" in text.lower():
            w = re.search(r"(?i)\b(apt\d{1,3}[a-z]?|sandworm|lazarus|turla|apt28|fancy bear|cozy bear|apt29)\b", text)
            intent = ("ioc_group", w.group(0) if w else text.strip())

    # Execute
    try:
        if intent and intent[0] == "ioc_group":
            group = intent[1]
            await cl.Message(content=f"🔎 Fetching IOC overview for **{group}**...").send()
            intel = claude_a1(system=SYS_THREAT_INTEL, user=prompt_for_apt_iocs(group))
            results["intel"]["apt_iocs"] = {"group": group, "content": intel}
            await cl.Message(content=intel).send()

        elif intent and intent[0] == "mitre":
            tech = intent[1]
            await cl.Message(content=f"🧭 Getting MITRE details for **{tech}**...").send()
            intel = claude_a1(system=SYS_THREAT_INTEL, user=prompt_for_mitre(tech))
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
            if not aggregated_iocs and not text:
                await cl.Message(content=HELP_A1 + "\n\n" + HELP_SHARED).send()
            elif not aggregated_iocs:
                await cl.Message(content="Try: `IOC APT28`, `MITRE T1547`, `ENRICH IP 8.8.8.8`, or upload a PDF/JSON.").send()

    except Exception as e:
        await cl.Message(content=f"❌ Error: {e}").send()

    # Save snapshot for A2 (also stash quick indicators if any)
    try:
        quick = aggregated_iocs.copy()
        
        rh = results.get("vt", {}).get("hash", {}).get("relationships", {})
        if isinstance(rh, dict):
            if isinstance(rh.get("contacted_domains"), list):
                quick.setdefault("domain", [])
                quick["domain"].extend([d.get("id") for d in rh["contacted_domains"] if isinstance(d, dict) and d.get("id")])
            if isinstance(rh.get("contacted_ips"), list):
                quick.setdefault("ipv4", [])
                quick["ipv4"].extend([d.get("id") for d in rh["contacted_ips"] if isinstance(d, dict) and d.get("id")])
        for k in list(quick.keys()):
            quick[k] = sorted(set(quick[k]))
        results["quick_indicators"] = quick

        save_session_payload(sid, results)
        await cl.Message(content=f"💾 Saved snapshot: `workspace/session_{sid}.json`").send()
    except Exception as e:
        await cl.Message(content=f"⚠️ Could not save session snapshot: {e}").send()

# Mode A2
async def handle_mode_a2(message: cl.Message, text: str, files: List[Any]):
    sess_iocs = cl.user_session.get("iocs")
    sess_id = cl.user_session.get("sid")

    # JSON is uploaded, load and flatten IOCs
    for f in files:
        try:
            with open(f.path, "r", encoding="utf-8") as fd:
                data = json.load(fd)
            iocs = flatten_iocs(data)
            cl.user_session.set("iocs", iocs)
            sid = data.get("session_id", "file")
            cl.user_session.set("sid", sid)
            await cl.Message(content=f"📦 Loaded session `{sid}` from file. {summarize_iocs(iocs)}").send()
        except Exception as e:
            await cl.Message(content=f"⚠️ Could not parse uploaded file `{getattr(f, 'name', 'file')}`: {e}").send()


    m_alert = re.match(r"(?i)^\s*ALERT\s+(.+)$", text)
    if m_alert:
           cq = m_alert.group(1).strip()
           if not cq:
              await cl.Message(content="Please provide an alert query: `ALERT <your_query>`").send()
              return

           sid = cl.user_session.get("sid")
           if not sid:
              sid = new_session_id()
              cl.user_session.set("sid", sid)

           await cl.Message(content=f"🚨 Running ALERT for session `{sid}` with query:\n```{cq}```").send()

           try:
                res = run_alerts_and_save(session_id=sid, cq=cq, inst=None)
                session_path = res.get("session_path")
                alerts_section = res.get("alerts", {})

                elements = []
                if session_path and os.path.exists(session_path):
                    elements.append(cl.File(name=os.path.basename(session_path), path=session_path))

                # produce a short, safe snippet of result for UI
                snippet = alerts_section.get("result")
                try:
                    snippet_preview = json.dumps(snippet, indent=2) if not isinstance(snippet, str) else snippet[:1000]
                except Exception:
                    snippet_preview = str(snippet)[:1000]

                preview = {
                    "query": cq,
                    "inst": alerts_section.get("inst"),
                    "timestamp": alerts_section.get("timestamp"),
                }

                await cl.Message(
                    content=(
                        f"✅ ALERT completed and saved to `{os.path.basename(session_path)}`.\n"
                        f"Preview meta:\n```json\n{json.dumps(preview, indent=2)}\n```\n"
                        f"Result snippet:\n```\n{snippet_preview}\n```"
                    ),
                    elements=elements,
                    ).send()
           except Exception as e:
               await cl.Message(content=f"❌ ALERT failed: {e}").send()
           return

    # If user types only "ALERT" without query, prompt them
    if re.match(r"(?i)^\s*ALERT\s*$", text):
        await cl.Message(content="Provide an alert query inline: `ALERT <your_query>`").send()
        return
    
    # Commands: USE, SHOW IOC, BUILD
    m = re.match(r"(?i)^\s*USE\s+([A-Za-z0-9_-]{4,})\s*$", text)
    if m:
        sid = m.group(1)
        try:
            data = load_session_json(sid)
            iocs = flatten_iocs(data)
            cl.user_session.set("iocs", iocs)
            cl.user_session.set("sid", sid)
            await cl.Message(content=f"🔗 Loaded session `{sid}`. {summarize_iocs(iocs)}").send()
        except Exception as e:
            await cl.Message(content=f"❌ {e}").send()
        return

    if text.upper().strip() == "SHOW IOC":
        if not sess_iocs:
            await cl.Message(content="No IOCs loaded yet. Use `USE <session_id>` or upload the a1 snapshot JSON.").send()
            return
        await cl.Message(content="```json\n" + json.dumps(sess_iocs, indent=2) + "\n```").send()
        return

    if text.upper().strip() == "BUILD":
        try:
            sid = cl.user_session.get("sid")
            if not sid:
                await cl.Message(content="No session loaded. Use `USE <session_id>` first.").send()
                return

            await cl.Message(content=f"🧱 Building Helix/Trellix huting questions for session `{sid}`…").send()
            built = build_queries_from_session(sid)
            quests = built.get("quests", [])
            plain = built.get("plain_queries", [])
            quests_path = built.get("quests_path")
            elements = []
            if quests_path and os.path.exists(quests_path):
                elements.append(cl.File(name=os.path.basename(quests_path), path=quests_path))

            preview = {
                "quests_count": len(quests),
                "plain_queries": plain[:5],
            }
            await cl.Message(
                content=(
                    f"✅ Generated **{len(quests)}** quests for `{sid}`.\n"
                    f"Saved: `workspace/{os.path.basename(quests_path)}`\n\n"
                    f"Preview:\n```json\n{json.dumps(quests[:5], indent=2)}\n```"
                ),
                elements=elements,
            ).send()
        except Exception as e:
            await cl.Message(content=f"❌ BUILD failed: {e}").send()
        return

    if text.upper().strip() == "HUNT":
        try:
            sid = cl.user_session.get("sid")
            if not sid:
                await cl.Message(content="No Session loaded, please load the required session").send()
                return
            qp = os.path.join(WORKSPACE_DIR, f"quests_{sid}.json")
            if not os.path.exists(qp):
                await cl.Message(content="Quests file not found").send()
                return
            with open(qp, "r", encoding="utf-8") as f:
                data = json.load(f)
            plain = data.get("plain_queries", [])

            if not plain:
                await cl.Message(content="No plain ").send()
                return
            tap = try_import_tap
            if not tap:
                await cl.Message(content="Module Not Found").send()
                return
            await cl.Message(content=f"Please Wait...running {len(plain)} queries...").send()

            results = []
            for idx, query in enumerate(plain, 1):
                try:
                    tap = pytap.Tap(skip_allowed_update=False)
                    res = tap.search(query, instances=["hexgcq656"],  page_size=1, time_range=100, include_events=True)
                    results.append({"index": idx, "query": query, "results": res})
                except Exception as e:
                    results.append({"index": idx, "query": query, "error": str(e)})
            out_path = os.path.join(WORKSPACE_DIR, f"hunt_{sid}.json")
            with open(out_path, "w", encoding="utf-8") as f:
                json.dump({"session_id": sid, "results": results}, f, indent=2)        
            
            elements = []
            if os.path.exists(out_path):
                elements.append(cl.File(name=os.path.basename(out_path), path=out_path))
            preview = results[:3]

            await cl.Message(
                content = (
                    f"Saved Results `workspace/{os.path.basename(out_path)}`\n"
                    f"Preview: \n```json\n{json.dumps(preview, indent=2)}\n```"
                ),
                elements=elements
            ).send()
        
        except Exception as e:
            await cl.Message(content="RUN FAILED {e}!").send()
    # Default help
    if not files and not text:
        await cl.Message(content=f"{HELP_A2}\n\n{HELP_SHARED}").send()
        return
    elif not files:
        await cl.Message(content="I can `USE <session_id>`, `SHOW IOC`, or `BUILD`, or `HUNT`. ").send()
