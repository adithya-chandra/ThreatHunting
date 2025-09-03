This is the POC to generate Threat Hunting Queries for an Alert by leveraging Claude, Chainlit and VirusTotal

Execute by running python -m chainlit run app.py

```
🏹 Threat Intel Enrichment (Mode: A1)

• Get IOCs for APT groups — IOC APT28

• MITRE ATT&CK details — MITRE T1547

• VirusTotal enrichment — ENRICH IP 1.2.3.4 or ENRICH HASH <hash>

Make sure you update tokens - AWS CLI, VT API before executing
```
MODE A2

```
.
🛠️ Helix/Trellix Query Builder (Mode: A2)
• Load A1 session — USE <session_id> (or upload session_*.json)
• View IOCs — SHOW IOC
• Build Hunting questions — BUILD (saves quests_<session_id>.json)
• Hunt for logs — HUNT (saves quests_<session_id>.json)
• Alerts from Helix — ALERT [in progress*] (saves session_<session_id>.json)

Note: ALERT command is in progress
```

Ref: 
https://docs.google.com/document/d/1qR75rquYVwQtfj6eoUwOu--6h_vzT7iiHASp3In9MvY/edit?usp=sharing
