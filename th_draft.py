
import boto3
from pytap import pytap
import json
import os
import requests
from dotenv import load_dotenv
import warnings
import ipaddress
import re
from typing import Dict, Any, List, Optional
warnings.filterwarnings("ignore")


load_dotenv()
VT_API_KEY = os.getenv("VT_API_KEY")
VT_BASE_URL = "https://www.virustotal.com/api/v3"


tap = pytap.Tap(skip_allowed_update=False)
if tap:
    print("\nFetching Alerts...")
alerts = tap.alerts(instances=["hexgcq656"], query="HX",query_field="message",limit=1)

alert_json = json.dumps(alerts, indent=2)
print("T1", type(alert_json))

for alert in alerts:
    print("Alerts Fetched:\n", alert)
    #print(type(alert))

print("\nAnalysing the alert ....")


alert_name = alert.get("message")
print("Alert:", alert_name)



bedrock = boto3.client("bedrock-runtime")

class_template ={
        "alerts","adtran_netvanta","aerohive_ap","airtight_ap","akamai_waf","alcatel_lucent_omniswitch","amazon_ssm_agent","apache_cassandra","apache_http_server","apache_modsecurity","arbor_peakflow","arcsight","aruba_clearpass","aruba_networks","atlassian","attivo_networks_botsink","aws_cloudfront","aws_elb","aws_s3","aws_vpc_flow","balabit_syslogng","barracuda_ngfw","barracuda_sslvpn","barracuda_waf","beyondtrust_beyondinsight","bind_dns","bitglass","bluecoat_http_proxy","bluecoat_ops","bradford_network_sentry","bro_conn","bro_dce_rpc","bro_dhcp","bro_dnp3","bro_dns","bro_dpd","bro_files","bro_ftp","bro_http","bro_intel","bro_irc","bro_kerberos","bro_known_certs","bro_known_hosts","bro_known_services","bro_loaded_scripts","bro_modbus","bro_mysql","bro_notice","bro_ntlm","bro_packet_filter","bro_pe","bro_radius","bro_rdp","bro_sip","bro_smb_auth","bro_smb_cmd","bro_smb_files","bro_smb_mapping","bro_smtp","bro_smtp_entities","bro_smtpurl","bro_snmp","bro_software","bro_ssh","bro_ssl","bro_syslog","bro_tunnel","bro_weird","bro_x509","brocade_vtm","brocade_vyatta_vrouter","bromium_vsentry","carbonblack_aw","carbonblack_defense","carbonblack_er","centrify_suite","checkpoint","checkpoint_firewall","checkpoint_http_proxy","checkpoint_ng_firewall","checkpoint_smartdefense","cisco_acs","cisco_asa","cisco_asa_cws","cisco_firepower","cisco_firepower_ips","cisco_firewall","cisco_flow","cisco_ftd","cisco_fwsm","cisco_hsrp","cisco_ids","cisco_ios","cisco_ips","cisco_ironport_email","cisco_ironport_http_proxy","cisco_ironport_mgmt","cisco_ise","cisco_nexus","cisco_pix","cisco_prime","cisco_routing_ace","cisco_vcs","cisco_vpn","cisco_wlc","citrix_ima","citrix_netscaler","clam_antivirus","claroty_ctd","claroty_medigate","claroty_ranger","cloudlock_api","codegreen_dlp","cofense_triage","collectd","corelight_dns","corelight_http","crowdstrike_falconhost","cyberark_pta","cyberark_vault","cylance_protect_ips","darktrace_dcip","dell_emc","dhclient_dhcp","dhcpd_dhcp","dnsmasq","docker","dovecot_email","duo_auth","epic","epic_healthcare","eset_av","eset_raserver","estreamer","extrahop","f5","f5_asm","f5_bigip","f5_bigip_apm","f5_bigip_asm","f5_vpn","fairwarning_ppm","fidelis_systems","forcepoint_dlp","forcepoint_email","forcepoint_firewall","forcepoint_http_proxy","forescout_counteract","forescout_nac","forgerock","forgerock_tomcat","fortinet_fortianalyzer","fortinet_fortigate","fortinet_fortimail","fortscale_uba","github","github_auth","gtb_inspector","guardicore_centra","haproxy_http","hexadite_airs","hp_unix","ibm_aix","ibm_bigfix","ibm_guardiant","ibm_os_390","ibm_proventia","ibm_qradar","ibm_webseal","ibm_websphere","ibm_wincollect","ibm_xgs","iboss_web_gw","ifilter_http_proxy","imperva_incapsula","imperva_rasp","imperva_securesphere","imperva_securesphere_datasecurity","imperva_securesphere_waf","inetd","infoblox_nios","infoblox_pyauth","jasig_cas","jboss_app_server","juniper_alg","juniper_firewall","juniper_flow","juniper_idp","juniper_netscreen","juniper_ops","juniper_radius","juniper_strm","juniper_vpn","kaspersky","kiteworks","lanscope","lastline","linux_nscd","linux_os","logback","lucent_firewall","lumension_detection_agent","macosx","manageengine_adauditplus","mandiant_mca","mandiant_mir","mandiant_mso","mcafee_epo","mcafee_esm","mcafee_ips","mcafee_nsp","menandmice_dns","meraki_cms","microsoft_ata","microsoft_systemcenter","ms_adfs","ms_dhcp","ms_dns","ms_exchange","ms_iis","ms_isa","ms_mcas_siemagent","ms_netlogon","ms_sam","ms_scom","ms_sharepoint","ms_tmg_firewall","ms_tmg_http_proxy","ms_windows_cluster","ms_windows_event","ms_windows_perfmon","ms_windows_powershell","nagios","nessus_network_monitor","netflow","nginx","nios_mobile","nortel_vpn","ntpd","oclc_ezproxy","oneidentity_safeguard","open_sftp","open_systems","opendns","openldap","openpgp","openvpn","oracle_auditing","oracle_oci","osirium_pam","ossec","paloalto_config","paloalto_correlation","paloalto_decryption","paloalto_firewall","paloalto_globalprotect","paloalto_gtp","paloalto_hipmatch","paloalto_http_proxy","paloalto_lightcyber","paloalto_system","paloalto_threat_data","paloalto_threat_file","paloalto_threat_flood","paloalto_threat_packet","paloalto_threat_scan","paloalto_threat_spyware","paloalto_threat_url","paloalto_threat_virus","paloalto_threat_vulnerability","paloalto_threat_wildfire","paloalto_traffic","paloalto_traps","paloalto_userid","pascard","pfsense_filterlog","php","ping_identity","postfix_mail_ta","postgresql","powerdns","powertech_interact","proofpoint_observeit","proofpoint_sendmail","proofpoint_siemapi","pulsesecure_vpn","puppet","pwc_bit","python","qmail_mta","redseal_cap","riverbed","rsa_auth_mgr","rsa_netwitness","rscope_conn","rscope_dns","rscope_files","rscope_http","rscope_smtp","rscope_ssl","rscope_syslog","rscope_weird","rsyslog","salt_minion","secureauth_idp","securitymatters_silentdefense","sendmail","silverfort","snmpd","snort","sonicwall","sonicwall_nsa","sonicwall_sra","sophos","sophos_utm","sourcefire","splunk","splunk_ops","splunk_stream","splunk_stream_dns","squid_http_proxy","stealthbits_stealthintercept","stunnel","sun_one_ldap","sun_solaris","surricata_http_proxy","symantec_brightmail","symantec_dcs","symantec_dlp","symantec_endpoint_protection","symantec_sdcss","symantec_server","tenable_nessus","thycotic_secretserver","tipping_point_ips","tofino_xenon","trend_micro_cm","trend_micro_deep_discover_analyzer","trend_micro_deep_discover_inspector","trend_micro_http_proxy","trend_micro_imsva","tripwire_enterprise","tripwire_ids","trustwave_http_proxy","unix","unix_abrt","unix_anacron","unix_atd","unix_audit","unix_cron","unix_cxtracker","unix_ftp","unix_healthcheck","unix_impi","unix_init","unix_kernel","unix_kprop","unix_mgmtd","unix_mon","unix_multipath","unix_nrpe","unix_ossec","unix_pam","unix_rgp","unix_scsi","unix_ssh","unix_statsd","unix_syslog","unix_xntpd","varonis_dataprivilege","vectra_ai","verdasys_digital_guardian","viewfinity","vmware_esx","vmware_esxi","vmware_horizon","vmware_mgmt","vmware_uag","vmware_vsphere","vormetric_dsm","vormetric_vfs","voya_voyasso","watchguard_firewall","waterfall_logger","waterfall_usg","websense_http_proxy","wti_dms_server","xecutor","xinetd","zerofox_threat_feed","zscaler","zscaler_proxy","zscaler_zpa","fireeye_ax_alert","fireeye_submission","fireeye_stats","fireeye_etp","fireeye_ex_alert","fireeye_ex_metadata","fireeye_fx_alert","fireeye_hx_alert","fireeye_nx","fireeye_hx_sysinfo","fireeye_hx_ioc","alertlogic","aws_cloudtrail","aws_cloudtrail_digest","aws_cloudwatch","aws_guardduty","aws_securityhub","azure_microsoft_windows_security_auditing","bitglass","box","canary","checkpoint_firewall","ciphercloud","ciphercloud","cisco_amp","cisco_umbrella","cisco_umbrella_dns","cloudflare","cloudflare","corelight_dod","crowdstrike","crowdstrike_fdr","csc_domain_manager","cyberark_epm","digitalguardian","druva","duo_auth","entrust_intellitrust","exabeam_findings","fireeye_cloudvisory","fireeye_dod","fireeye_mandiant_validation","fireeye_messaging_security","fireeye_vnx","forcepoint_proxy","gigya_audit","google_cloud","google_cloud_audit_logs","google_gsuite","hisac_ioc","iboss","imperva_attackanalytics","imperva_incapsula","inneractiv","kentik","mcafee_epo","mcafee_web_gw","mimecast","ms_azure","ms_azure_ad","ms_graph","ms_mcas","ms_office365","ms_sharepoint","ms_windows_defender","mvision","netra_syslog","netskope","okta","paloalto_config","paloalto_prisma","paloalto_system","paloalto_threat","paloalto_traffic","phishlabs","phishlabs_ioc","proofpoint_casb","proofpoint_pod","proofpoint_siemapi","qualys","salesforce","signalsciences","slack","sophos","squid_http_proxy","symantec_casb","symantec_sepmobile","symantec_vip","symantec_web_security_service","symantec_wss_bluecoat","teamviewer","trend_micro_ctrl_mgr","trend_micro_deep_discovery","trendmicro_apex_central","verizon_waf","zimperium","zscaler_proxy"
    }



# ToolUse
tool_config = {
    "tools": [
        {
            "toolSpec": {
                "name": "identify_security_categories",
                "description": "Categorize security alerts and recommend investigation techniques",
                "inputSchema": {
                    "json": {
                        "type": "object",
                        "properties": {
                            "category_id": {"type": "string"},
                            "investigation_ids": {"type": "array", "items": {"type": "string"}},
                            "reasoning": {"type": "string"}
                        },
                        "required": ["category_id", "investigation_ids"]
                    }
                }
            }
        },
        {
            "toolSpec": {
                "name": "generate_investigative_qna",
                "description": "Generate investigative questions and queries using alert and template",
                "inputSchema": {
                    "json": {
                        "type": "object",
                        "properties": {
                            "investigative_queries": {
                                "type": "array",
                                "description": "List of Q&A objects",
                                "items": {
                                    "type": "object",
                                    "properties": {
                                        "question": {"type": "string"},
                                        "query": {"type": "string"}
                                    },
                                    "required": ["question", "query"]
                                }
                            }
                        },
                        "required": ["investigative_queries"]
                    }
                }
            }
        }
    ],
    "toolChoice": {"auto": {}}
}


# 3. config

inference_config = {"maxTokens": 7824, "temperature": 0.5, "topP": 0.9}

system_messages = [
    {"text": "You are a SOC analyst. Your job is to reason over alerts and propose investigations strictly based on the guidelines given."}
]

# 1st Run prompt
user_msg_phase1 = {
    "role": "user",
    "content": [{
        "text": (
            "You are a security analyst. ALWAYS call the identify_security_categories tool. "
            "Return a category_id and investigation_ids. "
            f"Alert JSON: {json.dumps(alert)}"
        )
    }]
}

#1st run to nova
resp_phase1 = bedrock.converse(
    modelId="us.amazon.nova-lite-v1:0",
    messages=[user_msg_phase1],
    system=system_messages,
    inferenceConfig=inference_config,
    toolConfig=tool_config,
)
assistant_msg_phase1 = resp_phase1["output"]["message"]
print("\nAlert Categorisation: ", assistant_msg_phase1)

# Checking tooluse is used
tool_call = next(
    (item["toolUse"] for item in assistant_msg_phase1.get("content", []) if "toolUse" in item),
    None
)

# Define 1st ToolUse
def handle_identify_security_categories(alert_obj, category_id, investigation_ids, reasoning=""):
    return {
        "alert_id": alert_obj.get("id"),
        "category_id": category_id,
        "investigation_ids": investigation_ids,
        "reasoning": reasoning,
    }

tool_payload_phase1 = {}
if tool_call and tool_call["name"] == "identify_security_categories":
    inputs = tool_call.get("input", {})
    tool_payload_phase1 = handle_identify_security_categories(
        alert_obj=alert,
        category_id=inputs.get("category_id", "unknown"),
        investigation_ids=inputs.get("investigation_ids", []),
        reasoning=inputs.get("reasoning", "")
    )

    # tool_result_msg holds the config to replay it back to nova
    tool_result_msg = {
        "role": "user",
        "content": [{
            "toolResult": {
                "toolUseId": tool_call["toolUseId"],
                "status": "success",
                "content": [{"json": tool_payload_phase1}]
            }
        }]
    }

    # template for investigative queries
    style_template = {
        "searches1": [
            {
                "category": "Rule Hits by IPs",
                "header": "Were there any other rules that fired for this source IP? (60m Time Offset)",
                "id": "1",
                "relative time": 3600,
                "search": "has:detect_ruleids [agentip,srcipv4,dstipv4]=<%=agentip%> | groupby detect_rulenames"
            }
        ],
        "searches2": [
            {
                "header": "Are there any related alerts for hostname(s) in this alert? (4h Time Offset)",
                "id": "1",
                "relative time": 14400,
                "search": "class:alerts hostname:<%=hostname%> | table [class,message,id,risk,alert_type,state,alert_type_details.source,alert_type_details.destination]"
            }
        ]
    }
 
    #2nd Run config, Alert + Template
    user_msg_phase2 = {
        "role": "user",
        "content": [{
            "text": (
                "You are a security analyst. Use the generate_investigative_qna tool to generate atleast 4 investigative question-query pairs MUST FOLLOW ALL the guidelines"
                "Create NEW investigative question-query pairs in TRELLIX SIEM (Trellix Query Language) style using the alert below referring to given style_template."
                "YOU MUST REPLACE the variables within <%= %> with the corresponding values extracted from the given Alert"
                "Do NOT copy from template. Use it only for structure reference. Pick only header and search from the template"
                "new Queries should be simple and MUST NOT contain regex"
                "fields after pipe operator '|' MUST be only 1 of either groupby or table ONLY "
                "in the query, fields after TABLE or GROUPBY must only contain 1 variable. DO NOT use '[]' after groupby or table in the new query"
                "class value in the NEW investigative question-query pairs must be picked from 'class_template' ONLY"
                "YOU MUST REPLACE the variables within <%= %> with the corresponding values extracted from the given Alert"
                f"Alert: {json.dumps(alert)} "
                f"Class template: {class_template} "
                f"Style template: {json.dumps(style_template)}"
            )
        }]
    }

    # 2nd run to nova (1st run prompt + 1st nova reply on alert categorisation + tooluse results + 2nd run prompt  )
    followup_resp_qna = bedrock.converse(
        modelId="us.amazon.nova-lite-v1:0",
        messages=[user_msg_phase1, assistant_msg_phase1, tool_result_msg, user_msg_phase2],
        system=system_messages,
        inferenceConfig=inference_config,
        toolConfig=tool_config
    )

    assistant_msg_qna = followup_resp_qna["output"]["message"]
    print("\n2nd run: ", assistant_msg_qna)

    # Extract Questions and Queries
    tool_use_extract = next((item["toolUse"] for item in assistant_msg_qna["content"] if "toolUse" in item), None)

    if tool_use_extract:
        print(json.dumps(tool_use_extract, indent=2))

        iq = tool_use_extract["input"].get("investigative_queries", [])
        quests = [f"'{entry['query']}'" for entry in iq]
        #print("\nQuests:::", quests) 

        print("\nInvestigative Queries and its Response... \n")
        
        all_data = []
        for q in quests:
            cq = q.strip('"').strip("'")
            result = tap.search(cq, instances=["hexgcq656"],  page_size=1, time_range=100, include_events=True)
            results = json.dumps(result, indent=2)
            print("\nQuery: ", cq)
            print("Results:",results)
            all_data.append({"query": cq,
                         "results": results})

    if results:
        tool_config: Dict[str, Any] = {
        "tools": [
            {
            "toolSpec": {
                "name": "analyze_results_for_iocs",
                "description": "Analyze event results to identify IOCs, IOAs, and suggest new investigative queries",
                "inputSchema": {
                    "json": {
                        "type": "object",
                        "properties": {
                            "iocs": {
                                "type": "array",
                                "items": {"type": "string"}
                            },
                            "ioas": {
                                "type": "array",
                                "items": {"type": "string"}
                            },
                            "new_queries": {
                                "type": "array",
                                "items": {"type": "string"}
                            },
                            "reasoning": {
                                "type": "array",
                                "items": {"type": "string"}
                            }
                        },
                        "required": ["iocs", "ioas", "new_queries", "reasoning"]
                    }
                }
              }
             }
            ]
        }
        findings = [
            {
            "role": "user",
            "content": [
                     {
                            "text": (
                            "You are a cybersecurity analyst.\n"
                            "Here are the investigation queries and corresponding results:\n"
                            f"{all_data}\n"
                            "Analyze them thoroughly line by line, find security anomalies and indicators of compromises from the fields,  respond in JSON with the following fields:\n. Ignore Errors"
                            "- iocs: list of detected IOCs (IPs, hashes, domains) ONLY\n"
                            "- ioas: list of detected IOAs (behaviors)\n"
                            "- new_queries: list of recommended new investigative queries in Trellix Query Language following syntax with class_template data\n"
                            ""
                            )
                    }
                    ]
                }   
            ]
        rp = bedrock.converse(
         modelId ="us.amazon.nova-lite-v1:0",
         messages = findings,
         toolConfig = tool_config 
        )
        op1 = rp["output"]["message"]
       
        print("\nIOC/IOA:\n")
        for item in rp["output"]["message"]["content"]:
            if "toolUse" in item and "input" in item["toolUse"]:
                output = item["toolUse"]["input"]
                print("IOCs:", output.get("iocs", []))
                print("IOAs:", output.get("ioas", []))
                print("New Queries:", output.get("new_queries", []))
                print("Reasons:\n", output.get("reasoning", []))
                iocs = output.get("iocs", [])
        
        print("\n Enrichments...\n ")
        #nova_output = None
        #for items in rp["content"]:
        #    if "text" in items:
        #        nova_output = json.loads(items["text"])
        def check_ioc_type(ioc):
            # If it's a hash
            if len(ioc) in [32, 40, 64] and re.fullmatch(r"[a-fA-F0-9]+", ioc):
                return "hash"
            
            if re.fullmatch(r"[A-Za-z0-9_]+\\.[A-Za-z0-9_]+", ioc):
                prefix = ioc.split(".", 1)[0].lower()
                if prefix in {"backdoor", "virus", "trojan", "malware", "exploit"}:
                    return "malware"
    
            # If it contains letters and dots, treat as domain
            elif "." in ioc and re.search(r"[a-zA-Z]", ioc):
                return "domain"
    
            # Try IP address check
            
            ip_obj = ipaddress.ip_address(ioc)
            if ip_obj.is_private:
                    return "ignore"  # Skip privates
            return "ip"


        def query_vt(ioc, ioc_type):
            headers = {"x-apikey": VT_API_KEY}
            if ioc_type == "ip":
                url = f"{VT_BASE_URL}/ip_addresses/{ioc}"
            elif ioc_type == "hash":
                url = f"{VT_BASE_URL}/files/{ioc}"
            elif ioc_type == "domain":
                 url = f"{VT_BASE_URL}/domains/{ioc}"
            else:
                return []
    
            r = requests.get(url, headers=headers)
            if r.status_code != 200:
                return []
    
            data = r.json()
            tags = []
            if "data" in data and "attributes" in data["data"]:
                 attrs = data["data"]["attributes"]
                 if "tags" in attrs:
                    tags.extend(attrs["tags"])
                 if "last_analysis_results" in attrs:
                    for vendor, result in attrs["last_analysis_results"].items():
                        if result.get("category") == "malicious" and result.get("result"):
                            tags.append(result["result"])
            return list(set(tags))


        def query_vt_relationships(ioc: str, relationship: str = "communicating_files", limit: int = 10) -> List[str]:
            headers = {"x-apikey": VT_API_KEY}
            url = f"{VT_BASE_URL}/ip_addresses/{ioc}/relationships/{relationship}?limit={limit}"
            resp = requests.get(url, headers=headers)
            if resp.status_code != 200:
                return []
            data = resp.json().get("data", [])
            return [item.get("id") for item in data if isinstance(item, dict) and item.get("id")]
        

        def query_vt_domain_relationships(domain: str, relationship: str = "resolutions", limit: int = 10):
            headers = {"x-apikey": VT_API_KEY}
            url = f"{VT_BASE_URL}/domains/{domain}/relationships/{relationship}?limit={limit}"
            resp = requests.get(url, headers=headers)
            if resp.status_code != 200:
                return []
            items = resp.json().get("data", [])
            return [obj.get("id") for obj in items if isinstance(obj, dict) and obj.get("id")]


        ioc_analysis = []
        domain_analysis = []
        for ioc in iocs:
            rel = []
            ioc_type = check_ioc_type(ioc)
            if ioc_type == "ignore" :
                continue
            if ioc_type == "ip":
                vt_tags = query_vt(ioc, ioc_type)
                rel = query_vt_relationships(ioc, relationship="communicating_files")
                ref = query_vt_relationships(ioc, relationship="referrer_files")
                reso = query_vt_relationships(ioc, relationship="resolutions")
                ta = query_vt_relationships(ioc, relationship="related_threat_actors")
                ioc_analysis.append({
                  "ioc": ioc,
                 "type": ioc_type,
                 "vt_tags": vt_tags,
                 "relationships": rel,
                 "referrer_files": ref,
                 "resolutions": reso,
                  "APT": ta
                })
            elif ioc_type == "domain":
                resol = query_vt_domain_relationships(ioc, relationship="resolutions")
                resolutions = query_vt_domain_relationships(ioc, relationship="resolutions")
                referrer_files = query_vt_domain_relationships(ioc, relationship="referrer_files")
                threat_actors = query_vt_domain_relationships(ioc, relationship="related_threat_actors")

                domain_analysis.append({
                "domain": ioc,
                "resolutions": resolutions,
                "referrer_files": referrer_files,
                "threat_actors": threat_actors
                })

        final_output = {
            "ioc_enrichment": ioc_analysis, 
            "domain_enrichment": domain_analysis
        }
        print(json.dumps(final_output, indent=2))

        print("Analysing Enrichments, Generating Hunting Queries....")

        style1_template = {
          "searches1": [
            {

                "question": "Were there any other rules that fired for this source IP? (60m Time Offset)",
                "query": "has:detect_ruleids [agentip,srcipv4,dstipv4]=<%=agentip%>"
            }
          ],
          "searches2": [
            {
                "question": "Are there any related alerts for hostname(s) in this alert? (4h Time Offset)",
                "query": "class:alerts hostname:<%=hostname%>"
            }
          ]
        }

        field_templates ={
            "md5", "sha256", "pprocesspath", "process", "processpath", "srcipv4", "dstipv4", "dstport", "url", "domain"
        }

        messages = [
            {
            "role": "user",
            "content": [
            {
                "text": (
                    "You are a security analyst. Based on the enrichment data and templates provided below, generate HELIX SIEM style question-query pairs for Threat Hunting "
                    "generate NEW Helix (MQL) search queries for further investigation by following templates style1_template, field_template and class_template \n\n"
                    "EnrichmentData:\n" + json.dumps(final_output, indent=2) +
                    "fields in the NEW queries MUST be picked from field_template"
                    "YOU MUST replace the variables within <%= %> with the corresponding values extracted from the given Alert"
                    "Output should ONLY contain question and queries and nothing else"
                    f"Class template: {class_template} "
                    f"Field template: {field_templates}"
                    f"Style template: {json.dumps(style1_template)}"
                    )
                }
                ]
            }
        ]

        response = bedrock.converse(
        modelId="us.amazon.nova-lite-v1:0",
        messages=messages
        )

        assistant_msg = response["output"]["message"]
        for item in assistant_msg["content"]:
          if "text" in item:
            try:
                data = json.loads(item["text"])
                print("\nGenerated Queries:")
                print(json.dumps(data, indent=2))
            except json.JSONDecodeError:
                print(item["text"])
else:
    print("No tool call or unexpected tool name in 1st Run")