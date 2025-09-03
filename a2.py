# a2.py
"""
Query Builder
"""

from __future__ import annotations
import os
import re
import json
import time
from pytap import pytap
import logging
from typing import Dict, Any, List, Optional

import boto3
from botocore.config import Config
from dotenv import load_dotenv

load_dotenv()
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

AWS_REGION = os.getenv("AWS_REGION", "us-east-1")
MODEL_ID = os.getenv("BEDROCK_MODEL_ID", "us.anthropic.claude-3-5-sonnet-v2:0")
WORKSPACE_DIR = os.getenv("WORKSPACE_DIR", "./workspace")
os.makedirs(WORKSPACE_DIR, exist_ok=True)

# Claude
def _bedrock_client():
    cfg = Config(read_timeout=90, connect_timeout=10, retries={"max_attempts": 3})
    return boto3.client("bedrock-runtime", region_name=AWS_REGION, config=cfg)

def call_claude(
    system: str,
    user: str,
    temperature: float = 0.15,
    max_tokens: int = 2500,
) -> str:
    body = {
        "anthropic_version": "bedrock-2023-05-31",
        "max_tokens": max_tokens,
        "temperature": temperature,
        "system": system,
        "messages": [{"role": "user", "content": [{"type": "text", "text": user}]}],
    }
    brt = _bedrock_client()
    resp = brt.invoke_model(
        modelId=MODEL_ID,
        body=json.dumps(body).encode("utf-8"),
        accept="application/json",
        contentType="application/json",
    )
    payload = json.loads(resp["body"].read() if hasattr(resp["body"], "read") else resp["body"])
    blocks = payload.get("content", [])
    texts = [b.get("text", "") for b in blocks if b.get("type") == "text"]
    out = "\n".join([t for t in texts if t]).strip() or payload.get("output_text", "").strip()
    if not out:
        raise RuntimeError(f"No text in model response: {json.dumps(payload)[:500]}")
    return out


#alert data form helix
def run_alerts_and_save(session_id: str, cq: str, inst: Optional[List[str]] = None, timeout: int = 120) -> Dict[str, Any]:
    """
    Run tap.alerts(inst=[...], query=cq) and save results into workspace/session_<session_id>.json..
    - Merges saved alerts into existing session file if present, else creates a minimal session object.
    - Returns {"session_path": path, "alerts": alerts_section}
    """
    tap = pytap.Tap(skip_allowed_update=False)
    inst_list = inst if inst is not None else ["hexgcq656"]
    alerts_raw = tap.alerts(instances=["hexgcq656"], query=cq, query_field="message",limit=1)


    # 2) prepare session-style object and merge/save
    session_path = os.path.join(WORKSPACE_DIR, f"session_{session_id}.json")
    try:
        if os.path.exists(session_path):
            with open(session_path, "r", encoding="utf-8") as fh:
                session_obj = json.load(fh)
        else:
            session_obj = {"session_id": session_id, "timestamp": int(time.time()), "inputs": {}, "extracted_iocs": {}, "intel": {}, "vt": {}, "quick_indicators": {}}
    except Exception:
        session_obj = {"session_id": session_id, "timestamp": int(time.time()), "inputs": {}, "extracted_iocs": {}, "intel": {}, "vt": {}, "quick_indicators": {}}

    # add inputs and alerts section
    session_obj.setdefault("inputs", {})
    session_obj["inputs"]["alert_query"] = cq

    # ensure alerts_raw is JSON-serializable (serialize with default=str then reload if possible)
    try:
        serialized = json.loads(json.dumps(alerts_raw, default=str))
    except Exception:
        serialized = str(alerts_raw)

    session_obj["alerts"] = {
        "inst": inst_list,
        "query": cq,
        "result": serialized,
        "timestamp": int(time.time())
    }

    # persist
    with open(session_path, "w", encoding="utf-8") as fh:
        json.dump(session_obj, fh, indent=2)

    return {"session_path": session_path, "alerts": session_obj["alerts"]}


# a1 snapshot load
def load_session_json(session_id: str) -> Dict[str, Any]:
    p = os.path.join(WORKSPACE_DIR, f"session_{session_id}.json")
    if not os.path.exists(p):
        raise FileNotFoundError(f"Session file not found: {p}")
    with open(p, "r", encoding="utf-8") as f:
        return json.load(f)

# Flatten IOCs (VT IP rels)
_HASH_PATTERNS = {
    "sha256": re.compile(r"^[A-Fa-f0-9]{64}$"),
    "sha1":   re.compile(r"^[A-Fa-f0-9]{40}$"),
    "md5":    re.compile(r"^[A-Fa-f0-9]{32}$"),
}
_IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
_DOMAIN_RE = re.compile(r"\b(?!(?:\d{1,3}\.){3}\d{1,3})(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63}\b")
_FILENAME_RE = re.compile(r"\b[\w\-\.\s]+?\.(?:exe|dll|bat|cmd|ps1|scr|sys|js|vbs)\b", re.IGNORECASE)

def _add(coll: Dict[str, List[str]], kind: str, values: List[str]):
    if not values:
        return
    coll.setdefault(kind, [])
    for v in values:
        if isinstance(v, str) and v:
            coll[kind].append(v)

def _classify_hash(h: str) -> str:
    for k, rx in _HASH_PATTERNS.items():
        if rx.match(h):
            return k
    return ""

def flatten_iocs(session_obj: Dict[str, Any]) -> Dict[str, List[str]]:
    """ Enrichments
      - VT ip object: ip, communicating_files, referrer_files
      - intel text regex mining
    Output keys: ipv4, domain, sha256, sha1, md5, filename, hash
    """
    coll: Dict[str, List[str]] = {}

    qi = session_obj.get("quick_indicators") or {}
    if isinstance(qi, dict):
        for k, v in qi.items():
            if isinstance(v, list):
                _add(coll, k, v)

    ei = session_obj.get("extracted_iocs", {}) or {}
    if isinstance(ei, dict):
        for k, v in ei.items():
            if isinstance(v, list):
                _add(coll, k, v)

    vt = session_obj.get("vt", {}) or {}
    vt_ip = vt.get("ip", {}) or {}

    # 3a) top-level key IP
    ip_str = vt_ip.get("ip")
    if isinstance(ip_str, str) and _IPV4_RE.search(ip_str):
        _add(coll, "ipv4", [ip_str])

    for key in ["communicating_files", "referrer_files"]:
        items = vt_ip.get(key) or []
        if not isinstance(items, list):
            continue

        extracted: List[str] = []
        for it in items:
            if isinstance(it, str):
                extracted.append(it.strip())
            elif isinstance(it, dict) and it.get("id"):
                extracted.append(str(it["id"]).strip())

        for h in extracted:
            algo = _classify_hash(h)
            if algo:
                _add(coll, algo, [h])
            elif re.fullmatch(r"[A-Fa-f0-9]{32,64}", h or ""):
                _add(coll, "hash", [h])

    texts = []
    intel = session_obj.get("intel", {}) or {}
    if isinstance(intel, dict):
        if "apt_iocs" in intel:
            texts.append(intel["apt_iocs"].get("content", "") or "")
        if "mitre" in intel:
            texts.append(intel["mitre"].get("content", "") or "")
    joined = "\n".join(texts)

    _add(coll, "ipv4", list(set(_IPV4_RE.findall(joined))))
    _add(coll, "domain", list(set(_DOMAIN_RE.findall(joined))))
    _add(coll, "sha256", list(set(re.findall(_HASH_PATTERNS["sha256"], joined))))
    _add(coll, "sha1", list(set(re.findall(_HASH_PATTERNS["sha1"], joined))))
    _add(coll, "md5", list(set(re.findall(_HASH_PATTERNS["md5"], joined))))
    _add(coll, "filename", list(set(_FILENAME_RE.findall(joined))))

    union_hashes = set(coll.get("hash", []))
    for algo in ("sha256", "sha1", "md5"):
        union_hashes.update(coll.get(algo, []))
    coll["hash"] = sorted(union_hashes)


    for k in list(coll.keys()):
        coll[k] = sorted(set(filter(None, coll[k])))

    return coll

# style_template + LLM prompt → quests[]

style_template = {
    "searches1": [
        {
            "category": "Rule Hits by IPs",
            "question": "Were there any other rules that fired for this source IP?",
            "query": "has:detect_ruleids [agentip,srcipv4,dstipv4]=<%=agentip%> | groupby detect _rulenames"
        }
    ],
    "searches2": [
        {
            "question": "Are there any related alerts for hostname(s) in this alert? (4h Time Offset)",
            "query": "class:alerts rawmsg:<%=hostname%>| table [class,message,id,risk,alert_type,state,alert_type_details.source,alert_type_details.destination]"
        }
    ]
}

class_template ={
        "alerts","adtran_netvanta","aerohive_ap","airtight_ap","akamai_waf","alcatel_lucent_omniswitch","amazon_ssm_agent","apache_cassandra","apache_http_server","apache_modsecurity","arbor_peakflow","arcsight","aruba_clearpass","aruba_networks","atlassian","attivo_networks_botsink","aws_cloudfront","aws_elb","aws_s3","aws_vpc_flow","balabit_syslogng","barracuda_ngfw","barracuda_sslvpn","barracuda_waf","beyondtrust_beyondinsight","bind_dns","bitglass","bluecoat_http_proxy","bluecoat_ops","bradford_network_sentry","bro_conn","bro_dce_rpc","bro_dhcp","bro_dnp3","bro_dns","bro_dpd","bro_files","bro_ftp","bro_http","bro_intel","bro_irc","bro_kerberos","bro_known_certs","bro_known_hosts","bro_known_services","bro_loaded_scripts","bro_modbus","bro_mysql","bro_notice","bro_ntlm","bro_packet_filter","bro_pe","bro_radius","bro_rdp","bro_sip","bro_smb_auth","bro_smb_cmd","bro_smb_files","bro_smb_mapping","bro_smtp","bro_smtp_entities","bro_smtpurl","bro_snmp","bro_software","bro_ssh","bro_ssl","bro_syslog","bro_tunnel","bro_weird","bro_x509","brocade_vtm","brocade_vyatta_vrouter","bromium_vsentry","carbonblack_aw","carbonblack_defense","carbonblack_er","centrify_suite","checkpoint","checkpoint_firewall","checkpoint_http_proxy","checkpoint_ng_firewall","checkpoint_smartdefense","cisco_acs","cisco_asa","cisco_asa_cws","cisco_firepower","cisco_firepower_ips","cisco_firewall","cisco_flow","cisco_ftd","cisco_fwsm","cisco_hsrp","cisco_ids","cisco_ios","cisco_ips","cisco_ironport_email","cisco_ironport_http_proxy","cisco_ironport_mgmt","cisco_ise","cisco_nexus","cisco_pix","cisco_prime","cisco_routing_ace","cisco_vcs","cisco_vpn","cisco_wlc","citrix_ima","citrix_netscaler","clam_antivirus","claroty_ctd","claroty_medigate","claroty_ranger","cloudlock_api","codegreen_dlp","cofense_triage","collectd","corelight_dns","corelight_http","crowdstrike_falconhost","cyberark_pta","cyberark_vault","cylance_protect_ips","darktrace_dcip","dell_emc","dhclient_dhcp","dhcpd_dhcp","dnsmasq","docker","dovecot_email","duo_auth","epic","epic_healthcare","eset_av","eset_raserver","estreamer","extrahop","f5","f5_asm","f5_bigip","f5_bigip_apm","f5_bigip_asm","f5_vpn","fairwarning_ppm","fidelis_systems","forcepoint_dlp","forcepoint_email","forcepoint_firewall","forcepoint_http_proxy","forescout_counteract","forescout_nac","forgerock","forgerock_tomcat","fortinet_fortianalyzer","fortinet_fortigate","fortinet_fortimail","fortscale_uba","github","github_auth","gtb_inspector","guardicore_centra","haproxy_http","hexadite_airs","hp_unix","ibm_aix","ibm_bigfix","ibm_guardiant","ibm_os_390","ibm_proventia","ibm_qradar","ibm_webseal","ibm_websphere","ibm_wincollect","ibm_xgs","iboss_web_gw","ifilter_http_proxy","imperva_incapsula","imperva_rasp","imperva_securesphere","imperva_securesphere_datasecurity","imperva_securesphere_waf","inetd","infoblox_nios","infoblox_pyauth","jasig_cas","jboss_app_server","juniper_alg","juniper_firewall","juniper_flow","juniper_idp","juniper_netscreen","juniper_ops","juniper_radius","juniper_strm","juniper_vpn","kaspersky","kiteworks","lanscope","lastline","linux_nscd","linux_os","logback","lucent_firewall","lumension_detection_agent","macosx","manageengine_adauditplus","mandiant_mca","mandiant_mir","mandiant_mso","mcafee_epo","mcafee_esm","mcafee_ips","mcafee_nsp","menandmice_dns","meraki_cms","microsoft_ata","microsoft_systemcenter","ms_adfs","ms_dhcp","ms_dns","ms_exchange","ms_iis","ms_isa","ms_mcas_siemagent","ms_netlogon","ms_sam","ms_scom","ms_sharepoint","ms_tmg_firewall","ms_tmg_http_proxy","ms_windows_cluster","ms_windows_event","ms_windows_perfmon","ms_windows_powershell","nagios","nessus_network_monitor","netflow","nginx","nios_mobile","nortel_vpn","ntpd","oclc_ezproxy","oneidentity_safeguard","open_sftp","open_systems","opendns","openldap","openpgp","openvpn","oracle_auditing","oracle_oci","osirium_pam","ossec","paloalto_config","paloalto_correlation","paloalto_decryption","paloalto_firewall","paloalto_globalprotect","paloalto_gtp","paloalto_hipmatch","paloalto_http_proxy","paloalto_lightcyber","paloalto_system","paloalto_threat_data","paloalto_threat_file","paloalto_threat_flood","paloalto_threat_packet","paloalto_threat_scan","paloalto_threat_spyware","paloalto_threat_url","paloalto_threat_virus","paloalto_threat_vulnerability","paloalto_threat_wildfire","paloalto_traffic","paloalto_traps","paloalto_userid","pascard","pfsense_filterlog","php","ping_identity","postfix_mail_ta","postgresql","powerdns","powertech_interact","proofpoint_observeit","proofpoint_sendmail","proofpoint_siemapi","pulsesecure_vpn","puppet","pwc_bit","python","qmail_mta","redseal_cap","riverbed","rsa_auth_mgr","rsa_netwitness","rscope_conn","rscope_dns","rscope_files","rscope_http","rscope_smtp","rscope_ssl","rscope_syslog","rscope_weird","rsyslog","salt_minion","secureauth_idp","securitymatters_silentdefense","sendmail","silverfort","snmpd","snort","sonicwall","sonicwall_nsa","sonicwall_sra","sophos","sophos_utm","sourcefire","splunk","splunk_ops","splunk_stream","splunk_stream_dns","squid_http_proxy","stealthbits_stealthintercept","stunnel","sun_one_ldap","sun_solaris","surricata_http_proxy","symantec_brightmail","symantec_dcs","symantec_dlp","symantec_endpoint_protection","symantec_sdcss","symantec_server","tenable_nessus","thycotic_secretserver","tipping_point_ips","tofino_xenon","trend_micro_cm","trend_micro_deep_discover_analyzer","trend_micro_deep_discover_inspector","trend_micro_http_proxy","trend_micro_imsva","tripwire_enterprise","tripwire_ids","trustwave_http_proxy","unix","unix_abrt","unix_anacron","unix_atd","unix_audit","unix_cron","unix_cxtracker","unix_ftp","unix_healthcheck","unix_impi","unix_init","unix_kernel","unix_kprop","unix_mgmtd","unix_mon","unix_multipath","unix_nrpe","unix_ossec","unix_pam","unix_rgp","unix_scsi","unix_ssh","unix_statsd","unix_syslog","unix_xntpd","varonis_dataprivilege","vectra_ai","verdasys_digital_guardian","viewfinity","vmware_esx","vmware_esxi","vmware_horizon","vmware_mgmt","vmware_uag","vmware_vsphere","vormetric_dsm","vormetric_vfs","voya_voyasso","watchguard_firewall","waterfall_logger","waterfall_usg","websense_http_proxy","wti_dms_server","xecutor","xinetd","zerofox_threat_feed","zscaler","zscaler_proxy","zscaler_zpa","fireeye_ax_alert","fireeye_submission","fireeye_stats","fireeye_etp","fireeye_ex_alert","fireeye_ex_metadata","fireeye_fx_alert","fireeye_hx_alert","fireeye_nx","fireeye_hx_sysinfo","fireeye_hx_ioc","alertlogic","aws_cloudtrail","aws_cloudtrail_digest","aws_cloudwatch","aws_guardduty","aws_securityhub","azure_microsoft_windows_security_auditing","bitglass","box","canary","checkpoint_firewall","ciphercloud","ciphercloud","cisco_amp","cisco_umbrella","cisco_umbrella_dns","cloudflare","cloudflare","corelight_dod","crowdstrike","crowdstrike_fdr","csc_domain_manager","cyberark_epm","digitalguardian","druva","duo_auth","entrust_intellitrust","exabeam_findings","fireeye_cloudvisory","fireeye_dod","fireeye_mandiant_validation","fireeye_messaging_security","fireeye_vnx","forcepoint_proxy","gigya_audit","google_cloud","google_cloud_audit_logs","google_gsuite","hisac_ioc","iboss","imperva_attackanalytics","imperva_incapsula","inneractiv","kentik","mcafee_epo","mcafee_web_gw","mimecast","ms_azure","ms_azure_ad","ms_graph","ms_mcas","ms_office365","ms_sharepoint","ms_windows_defender","mvision","netra_syslog","netskope","okta","paloalto_config","paloalto_prisma","paloalto_system","paloalto_threat","paloalto_traffic","phishlabs","phishlabs_ioc","proofpoint_casb","proofpoint_pod","proofpoint_siemapi","qualys","salesforce","signalsciences","slack","sophos","squid_http_proxy","symantec_casb","symantec_sepmobile","symantec_vip","symantec_web_security_service","symantec_wss_bluecoat","teamviewer","trend_micro_ctrl_mgr","trend_micro_deep_discovery","trendmicro_apex_central","verizon_waf","zimperium","zscaler_proxy"
    }

SYS_QUERY_BUILDER = """You are a SOC detection engineer generating Helix/Trellix SIEM searches.
Follow the reference "style_template" and "class_template" the user provides.
Return ONLY JSON with a top-level "quests" array; each item MUST be:
  {"category": string, "question": string, "query": string}
Use the provided IOCs (IPs, domains, hashes, filenames) to tailor searches.
Prefer Helix/Trellix-style fields from the style_template (e.g., agentip, srcipv4, dstipv4, hostname, sha256, md5).
Include both IOC matches and investigative pivots.
Keep queries executable; Helix-style placeholders like <%=var%> are acceptable.
No commentary, no markdown — ONLY JSON.
"""

def prompt_for_quests(iocs: Dict[str, List[str]]) -> str:
    payload = {
        "style_template": style_template,
        "iocs": {
            "ipv4": iocs.get("ipv4", [])[:100],
            "domain": iocs.get("domain", [])[:100],
            "hash": iocs.get("hash", [])[:100],
            "filename": iocs.get("filename", [])[:100],
        },
        "output_contract": {
            "type": "object",
            "required": ["quests"],
            "properties": {
                "quests": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "required": ["query"],
                        "properties": {
                            "category": {"type": "string"},
                            "question": {"type": "string"},
                            "query": {"type": "string"}
                        }
                    }
                }
            }
        },
        "instructions": "Generate ONLY JSON with 'quests' containing Helix/Trellix queries."
    }
    return json.dumps(payload, indent=2)

def _parse_quests(model_text: str) -> List[Dict[str, str]]:
    s = model_text.strip()
    try:
        obj = json.loads(s)
        q = obj.get("quests", [])
        if isinstance(q, list) and all(isinstance(x, dict) and "query" in x for x in q):
            return q
    except Exception:
        pass
    m = re.search(r"\{.*\}", s, flags=re.DOTALL)
    if m:
        try:
            obj = json.loads(m.group(0))
            q = obj.get("quests", [])
            if isinstance(q, list):
                return q
        except Exception:
            pass
    raise ValueError("Model output was not valid JSON with a 'quests' array.")

#plain queries
def _strip_quotes(s: str) -> str:
    out = (s or "").strip()
    while out.startswith('"') and out.endswith('"') and len(out) >= 2:
        out = out[1:-1].strip()
    return out

def extract_plain_queries(quests: List[Dict[str, str]]) -> List[str]:
    plain: List[str] = []
    for q in quests:
        qtext = q.get("query") or ""
        plain.append(_strip_quotes(qtext))
    return [p for p in plain if p]

# BUILD: generate quests and save 
def build_queries_from_session(
    session_id: str,
    temperature: float = 0.12,
    max_tokens: int = 2500,
    save_md: bool = True,
) -> Dict[str, Any]:
    data = load_session_json(session_id)
    iocs = flatten_iocs(data)
    user_payload = prompt_for_quests(iocs)
    model_out = call_claude(system=SYS_QUERY_BUILDER, user=user_payload, temperature=temperature, max_tokens=max_tokens)
    quests = _parse_quests(model_out)
    plain_queries = extract_plain_queries(quests)

    quests_path = os.path.join(WORKSPACE_DIR, f"quests_{session_id}.json")
    with open(quests_path, "w", encoding="utf-8") as f:
        json.dump({"session_id": session_id, "quests": quests, "plain_queries": plain_queries}, f, indent=2)

    artifact_path: Optional[str] = None
    if save_md:
        artifact_path = os.path.join(WORKSPACE_DIR, f"queries_{session_id}.md")
        with open(artifact_path, "w", encoding="utf-8") as f:
            f.write("# Helix/Trellix SIEM Quests\n\n")
            f.write("## IOC snapshot\n\n")
            f.write("```json\n" + json.dumps(iocs, indent=2) + "\n```\n\n")
            f.write("## Quests (generated)\n\n")
            f.write("```json\n" + json.dumps(quests, indent=2) + "\n```\n\n")
            f.write("## Plain queries (no quotes)\n\n")
            f.write("```json\n" + json.dumps(plain_queries, indent=2) + "\n```\n")

    return {
        "session_id": session_id,
        "iocs": iocs,
        "quests": quests,
        "plain_queries": plain_queries,
        "quests_path": quests_path,
        "artifact_path": artifact_path,
        "raw_model_output": model_out,
    }

def build_queries_from_file(
    path_to_session_json: str,
    temperature: float = 0.12,
    max_tokens: int = 2500,
    save_md: bool = True,
) -> Dict[str, Any]:
    with open(path_to_session_json, "r", encoding="utf-8") as f:
        data = json.load(f)

    session_id = data.get("session_id", "file")
    iocs = flatten_iocs(data)
    user_payload = prompt_for_quests(iocs)
    model_out = call_claude(system=SYS_QUERY_BUILDER, user=user_payload, temperature=temperature, max_tokens=max_tokens)
    quests = _parse_quests(model_out)
    plain_queries = extract_plain_queries(quests)

    quests_path = os.path.join(WORKSPACE_DIR, f"quests_{session_id}.json")
    with open(quests_path, "w", encoding="utf-8") as f:
        json.dump({"session_id": session_id, "quests": quests, "plain_queries": plain_queries}, f, indent=2)

    artifact_path: Optional[str] = None
    if save_md:
        artifact_path = os.path.join(WORKSPACE_DIR, f"queries_{session_id}.md")
        with open(artifact_path, "w", encoding="utf-8") as f:
            f.write("# Helix/Trellix SIEM Quests\n\n")
            f.write("## IOC snapshot\n\n")
            f.write("```json\n" + json.dumps(iocs, indent=2) + "\n```\n\n")
            f.write("## Quests (generated)\n\n")
            f.write("```json\n" + json.dumps(quests, indent=2) + "\n```\n\n")
            f.write("## Plain queries (no quotes)\n\n")
            f.write("```json\n" + json.dumps(plain_queries, indent=2) + "\n```\n")

    return {
        "session_id": session_id,
        "iocs": iocs,
        "quests": quests,
        "plain_queries": plain_queries,
        "quests_path": quests_path,
        "artifact_path": artifact_path,
        "raw_model_output": model_out,
    }

# =========================================================
# Optional local test
# =========================================================
if __name__ == "__main__":
    sid = os.environ.get("TEST_SESSION_ID", "").strip()
    if not sid:
        print("Set TEST_SESSION_ID to an existing a1 snapshot id.")
    else:
        try:
            built = build_queries_from_session(sid, save_md=False)
            print("quests saved:", built["quests_path"])
            print("plain queries:", built["plain_queries"][:3])
        except Exception as e:
            print("ERROR:", e)
