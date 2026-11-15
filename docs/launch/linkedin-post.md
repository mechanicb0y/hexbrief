# LinkedIn launch post (draft for the owner's review; the owner posts it)

> Attach the 60–90 s vertical demo video (see "Video shot list" below) and put the repo link in the first comment, or in the post if you prefer.

---

Can a 4 GB laptop GPU write a threat intel brief that doesn't make things up?

Every morning, a SOC team needs one page that says what changed overnight, whether it touches them, and what to do first. The public intel is out there, but it's scattered across feeds and formats, and much of it is noise.

So I built HexBrief. It's open source:
🔹 Pulls free feeds (MITRE ATT&CK over TAXII 2.1, CISA KEV, abuse.ch, AlienVault OTX, CIRCL) into MISP and OpenCTI as STIX 2.1
🔹 Merges and ranks the last 24 hours with written rules: KEV, active exploitation, corroboration, relevance to education and ASEAN
🔹 A local LLM (Ollama, nothing leaves the laptop) writes the narrative
🔹 A validator rejects any IP, domain, hash, CVE or ATT&CK ID that isn't in the source data. If the model can't pass, the brief ships facts-only
🔹 Publishes Markdown, HTML, PDF and a STIX 2.1 Report over TAXII, and only TLP:CLEAR goes to the public archive

Three things I learned:
1️⃣ Make the model's job small. Facts come from data; the LLM only writes prose and cites findings by ID. In my benchmark, 0 invented facts in 9 of 9 runs.
2️⃣ Retries can make things worse. My first unattended run overflowed the model's context with retries. Now the best faithful answer is kept.
3️⃣ Fail closed on sharing. Unmarked data is treated as TLP:AMBER, and indicators are defanged everywhere humans read them.

Try it in 5 minutes with no keys: `pip install .` then `hexbrief demo`

🔗 github.com/mechanicb0y/hexbrief
📰 Daily archive: mechanicb0y.github.io/hexbrief

#ThreatIntelligence #CTI #STIX #TAXII #MISP #OpenCTI #CyberSecurity #LLM #Python

---

## Video shot list (60–90 s, vertical 1080×1920; the owner records it)
1. (0–5 s) Hook text over the HTML brief: "A threat brief written by a local AI that can't invent IOCs."
2. (5–20 s) Terminal: `hexbrief demo` running, then open `out\demo\brief.html` and scroll the TLP strip, top threats and KEV table.
3. (20–40 s) Show the validator: run `pytest tests/test_engine.py -k planted -q` and point at the planted fake IP never reaching the output.
4. (40–55 s) OpenCTI at 127.0.0.1:8088: the day's Report and its linked objects. Show TLP:CLEAR data only.
5. (55–75 s) The GitHub Pages archive and the README diagram.
6. (75–90 s) Close on the repo URL.

Before recording: close every browser tab except these, hide the taskbar and notifications, and make sure no `.env` file, token or non-CLEAR data is on screen.

## LinkedIn Projects / Featured entry
**HexBrief: grounded daily threat-intel brief.** Free feeds go over STIX/TAXII into MISP and OpenCTI. A local LLM writes a daily brief, and a validator blocks invented indicators. The brief is published as a STIX 2.1 Report over TAXII 2.1 and to a TLP:CLEAR archive. Python, Docker, Ollama, GitHub Actions.
Link: https://github.com/mechanicb0y/hexbrief
