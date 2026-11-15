# HexBrief daily threat brief: 2026-11-15

> **TLP:CLEAR**: may be shared publicly.
> Window: 2026-11-14 22:52 → 2026-11-15 22:52 (Asia/Kuala_Lumpur). Generated 2026-11-15 22:52 MYT.

## Bottom line up front

AI-driven attack frameworks like BOSSAI and CyberStrikeAI are actively targeting the education sector, while critical infrastructure vulnerabilities in UnrealIRCd and Check Point products remain on CISA's KEV list. Universities must prioritize patching known CVEs and monitoring for credential theft operations that exploit misconfigured cloud services.

## Top threats

### 1. BOSSAI AI Mesh Targets Education and Emergency Services

*Findings: [F3](#f3)*

The BOSSAI campaign utilizes a mesh of 12 AI agents to exfiltrate student data from Thai universities and medical records from Taiwan, demonstrating the threat of autonomous AI orchestration in education.

**Recommended actions**
- Monitor for C2 activity associated with identified BOSSAI infrastructure.
- Review access controls for cloud services handling student data.
- Implement network segmentation to limit lateral movement.

### 2. CyberStrikeAI Framework Targets Educational Institutions

*Findings: [F7](#f7)*

This open-source framework combines LLM orchestration with traditional C2 to perform reconnaissance, privilege escalation, and data exfiltration against educational institutions in Africa and Latin America.

**Recommended actions**
- Block identified CyberStrikeAI C2 servers at the perimeter.
- Scan for compromised SQL Server infrastructure.
- Deploy endpoint detection for credential dumping.

### 3. Critical Vulnerabilities Added to CISA KEV

*Findings: [F5](#f5), [F6](#f6)*

CVE-2026-114713 in UnrealIRCd and CVE-2026-123039 in Check Point products allow remote code execution or root command injection, with federal due dates set for 2026-11-16.

**Recommended actions**
- Patch UnrealIRCd and Check Point systems immediately.
- Disable world-writable sockets on Gaia OS DynamicCLI daemons.
- Verify server-to-server communication protocols.

### 4. KeyHunter Operation Targets Academic Credentials

*Findings: [F1](#f1)*

The KeyHunter actor harvested 2,233 API keys from misconfigured cloud infrastructure and created fraudulent student accounts at major universities.

**Recommended actions**
- Audit cloud configurations for exposed API keys on Vercel, Netlify, and Railway.
- Enable multi-factor authentication for all administrative accounts.
- Monitor for unauthorized student account creation.

### 5. Opportunistic Scanning of AI Development Platforms

*Findings: [F2](#f2)*

Attackers are scanning Langflow and other AI platforms for unauthenticated remote code execution vulnerabilities to harvest cloud credentials and model API keys.

**Recommended actions**
- Patch identified CVEs in AI development platforms.
- Implement network segmentation for AI/ML tools.
- Monitor for probing activity on application-building platforms.

## New CISA KEV entries

| CVE | Vulnerability | Ransomware |
|---|---|---|
| CVE-2026-114713 | UnrealIRCd Improper Neutralization of Delimiters Vulnerability |  |
| CVE-2026-123039 | Check Point Multiple Products Incorrect Permission Assignment for Critical Resource Vulnerability |  |

## ATT&CK techniques seen

`T1018` (3) · `T1105` (3) · `T1059.001` (3) · `T1190` (3) · `T1543.003` (3) · `T1053.005` (2) · `T1046` (2) · `T1505.003` (2) · `T1078` (2) · `T1090` (2) · `T1059.004` (2) · `T1027` (2) · `T1133` (2) · `T1059` (2) · `T1595.002` (2) · `T1552` (2) · `T1590` (2) · `T1083` (2) · `T1595` (2) · `T1082` (2) · `T1113` (2) · `T1071` (2) · `T1003.002` (2) · `T1003.001` (2) · `T1136.001` (2)

## Education and Malaysia/ASEAN watch

The BOSSAI campaign \[F3\] confirmed breaches involving student data from Thai universities, indicating active targeting of the ASEAN region's educational sector alongside Taiwan and Mexico.

## Trends

AI-driven automation is converging with traditional attack vectors to target education and critical infrastructure.

## Findings

### <a id="f1"></a>F1: KeyHunter Operation: Harvard Alumni Data, Stanford Applications and LLM Key Theft

- **Score 70**: +15 exploited in the wild, +10 confidence 100, +20 education sector, +20 Malaysia, +5 analysed report
- **Sources:** AlienVault OTX · **TLP:** TLP:CLEAR · **Confidence:** 100
- **CVEs:** CVE-2026-41940

A Chinese-speaking threat actor identified as leepsmarts conducted a multi-vector operation combining LLM API credential theft with academic fraud targeting 20 universities. The campaign harvested 2,233 API keys from misconfigured cloud infrastructure across platforms like Vercel, Netlify, and Railway, with 12 marked valid. The actor created fraudulent student accounts at institutions including NYU, UC Berkeley, and Oregon State, while processing 195 Harvard alumni records from a torrent-distributed dataset. The operation employed AI agent frameworks through Telegram bots for automated scanning, validation, and account creation. Parallel financial fraud activities included a Harmony ONE cryp

### <a id="f2"></a>F2: Attackers Target AI Development Platform Langflow

- **Score 47**: +15 exploited in the wild, +10 confidence 100, +6 education among 6 sectors, +5 government sector, +3 ASEAN among 16 countries, +3 ATT&amp;CK-mapped, +5 analysed report
- **Sources:** AlienVault OTX · **TLP:** TLP:CLEAR · **Confidence:** 100
- **CVEs:** CVE-2014-8361, CVE-2016-10372, CVE-2016-20016, CVE-2016-4800, CVE-2017-7921, CVE-2017-9841, CVE-2018-14028, CVE-2018-20062, CVE-2019-17621, CVE-2019-7256, CVE-2020-15505, CVE-2021-21974, CVE-2021-26855, CVE-2021-33044, CVE-2021-34523, CVE-2021-3493, CVE-2021-35394, CVE-2021-36380, CVE-2021-4034, CVE-2022-21894, CVE-2022-26134, CVE-2022-26289, CVE-2022-30190, CVE-2022-31199, CVE-2022-35555, CVE-2022-36553, CVE-2022-37055, CVE-2022-41082, CVE-2022-47986, CVE-2023-1389, CVE-2023-22518, CVE-2023-26801, CVE-2023-2868, CVE-2023-34362, CVE-2023-36025, CVE-2023-41011, CVE-2023-46604, CVE-2023-46805, CVE-2024-10914, CVE-2024-10915, CVE-2024-21412, CVE-2024-21887, CVE-2024-23624, CVE-2024-23625, CVE-2024-32281, CVE-2024-32292, CVE-2024-32314, CVE-2024-3400, CVE-2024-35340, CVE-2024-3721, CVE-2024-40766, CVE-2024-44000, CVE-2024-4577, CVE-2024-46048, CVE-2024-7029, CVE-2024-7344, CVE-2025-0994, CVE-2025-21042, CVE-2025-29927, CVE-2025-3248, CVE-2025-34035, CVE-2025-34037, CVE-2025-49704, CVE-2025-49706, CVE-2025-53770, CVE-2025-53771, CVE-2025-55182, CVE-2025-55184, CVE-2025-6264, CVE-2025-67038, CVE-2026-0768, CVE-2026-109618, CVE-2026-109619, CVE-2026-115560, CVE-2026-21509, CVE-2026-25085, CVE-2026-36356, CVE-2026-4020, CVE-2026-46300, CVE-2026-87827
- **ATT&CK:** T1016, T1018, T1021, T1021.004, T1027, T1027.004, T1033, T1036, T1036.004, T1037, T1040, T1046, T1048, T1049, T1053.005, T1053.006, T1055, T1056.001, T1057, T1059, T1059.001, T1059.004, T1059.005, T1059.006, T1068, T1070, T1070.002, T1070.003, T1070.004, T1070.006, T1071, T1071.001, T1071.003, T1071.004, T1078, T1082, T1083, T1090, T1090.002, T1090.003, T1095, T1102, T1105, T1106, T1113, T1132.001, T1133, T1134, T1136, T1140, T1189, T1190, T1203, T1204, T1204.002, T1219, T1486, T1489, T1496, T1497.001, T1497.003, T1498, T1498.001, T1505, T1505.003, T1543.002, T1543.003, T1548, T1548.001, T1552, T1552.001, T1553, T1562, T1562.001, T1566.001, T1566.002, T1568.002, T1571, T1572, T1573, T1573.001, T1574, T1574.002, T1590, T1595, T1595.002
- **Malware:** Cling, ClingSTUN, Remcos, Warlock, XMRIG, YobaDropper, YobaLoader

In September 2026, F5 Labs detected 405 exploitation attempts targeting CVE-2026-0768, an unauthenticated remote code execution vulnerability in Langflow AI application-building platform, originating from 55 distinct IP addresses. This marks the first observation of an AI/ML development platform RCE in opportunistic internet-wide scanning. Captured payloads included capability probing with unique markers, timing-based execution checks, and environment harvesting attempts aimed at extracting cloud credentials, model API keys, and database secrets. Activity came primarily from two infrastructure clusters: Google Cloud hosts using environment-harvesting payloads with forged AI-crawler User-Agen

### <a id="f3"></a>F3: BOSSAI: Inside the AI attack mesh that targeted Taiwan's emergency services

- **Score 46**: +10 confidence 100, +20 education sector, +5 government sector, +3 ASEAN among 14 countries, +3 ATT&amp;CK-mapped, +5 analysed report
- **Sources:** AlienVault OTX · **TLP:** TLP:CLEAR · **Confidence:** 100
- **ATT&CK:** T1003, T1018, T1046, T1059, T1071, T1078, T1083, T1090, T1105, T1110, T1133, T1190, T1213, T1552, T1567, T1589, T1590, T1590.005, T1592, T1595

Acronis Threat Research Unit identified a single operator utilizing a mesh of 12 AI agents called BOSSAI to conduct persistent campaigns across 11 countries. The attacker deployed both abliterated and commercial AI models working in specialized roles - infrastructure builders, vulnerability scanners, and active exploitation agents. Primary targets included emergency services, universities, financial institutions, and government systems in Taiwan, Thailand, and Mexico. Confirmed breaches involved exfiltration of medical records from Taipei emergency services, student data from Thai universities, and collection of over 200,000 Mexican residential phone records. Commercial AI models repeatedly

### <a id="f4"></a>F4: HexBrief daily threat brief 2026-11-15

- **Score 45**: +10 new in the last 24 h, +10 confidence 100, +20 education sector, +5 analysed report
- **Sources:** HexBrief · **TLP:** TLP:CLEAR · **Confidence:** 100

\# HexBrief daily threat brief: 2026-11-15 &gt; \*\*TLP:CLEAR\*\*: may be shared publicly. &gt; Window: 2026-11-14 22:24 → 2026-11-15 22:24 \(Asia/Kuala\_Lumpur\). Generated 2026-11-15 22:24 MYT. \#\# Bottom line up front Today's intelligence highlights a convergence of AI-driven automation in cyberattacks, with frameworks like BOSSAI and CyberStrikeAI targeting education sectors alongside critical infrastructure. Universities face dual threats from credential theft operations and sophisticated mobile malware campaigns exploiting supply chain compromises. \#\# Top threats \#\#\# 1. BOSSAI AI Mesh Targets Education and Emergency Services \*Findings: \[F3\]\(\#f3\)\* The BOSSAI campaign utilizes a mesh of 12 AI ag

### <a id="f5"></a>F5: CVE-2026-114713: UnrealIRCd Improper Neutralization of Delimiters Vulnerability

- **Score 44**: +30 in CISA KEV, +5 new in the last 72 h, +9 confidence 95
- **Sources:** CISA KEV · **TLP:** TLP:CLEAR · **Confidence:** 95
- **CVEs:** CVE-2026-114713

UnrealIRCd UnrealIRCd contains an improper neutralization of delimiters vulnerability that allows any user on a network with two or more linked servers to inject server-to-server commands that are executed with server authority. Added to CISA KEV on 2026-11-13; federal due date 2026-11-16.

### <a id="f6"></a>F6: CVE-2026-123039: Check Point Multiple Products Incorrect Permission Assignment for Critical Resource Vulnerability

- **Score 44**: +30 in CISA KEV, +5 new in the last 72 h, +9 confidence 95
- **Sources:** CISA KEV · **TLP:** TLP:CLEAR · **Confidence:** 95
- **CVEs:** CVE-2026-123039

Check Point Firewall, Multi-Domain Security Management Server, Scalable Platforms, Security Gateway, and Security Management Server contain an incorrect permissions assignment for critical resources vulnerability when the Gaia OS DynamicCLI daemon runs as root and listens on a world-writable local socket without authenticating connecting processes. An authenticated local user can send a command to the socket and have it executed as root. Added to CISA KEV on 2026-11-13; federal due date 2026-11-16.

### <a id="f7"></a>F7: CyberStrikeAI attacks educational institutions

- **Score 38**: +10 confidence 100, +20 education sector, +3 ATT&amp;CK-mapped, +5 analysed report
- **Sources:** AlienVault OTX · **TLP:** TLP:CLEAR · **Confidence:** 100
- **ATT&CK:** T1003.001, T1003.002, T1003.003, T1018, T1021.002, T1021.006, T1053.005, T1059.001, T1069.002, T1082, T1087.002, T1105, T1113, T1136.001, T1213.001, T1482, T1543.003, T1550.001, T1558.001, T1558.003, T1570
- **Malware:** CyberStrikeAI, Mimikatz, NodeRabbit, PollCat

An open-source framework called CyberStrikeAI was used in real-world attacks against educational institutions across Africa and Latin America. The framework combines LLM-based orchestration with a traditional C2 server, where an AI model on the server plans actions and generates commands while an implant executes them on compromised hosts. Attackers initially gained access through compromised SQL Server infrastructure, then deployed the CyberStrikeAI agent which performed reconnaissance, privilege escalation, credential dumping, lateral movement, and data exfiltration. The AI orchestrator automated post-exploitation activities that traditionally require manual operator intervention, reducing

### <a id="f8"></a>F8: Dark Web Profile: CyberXero

- **Score 38**: +15 exploited in the wild, +10 confidence 100, +5 government sector, +3 ATT&amp;CK-mapped, +5 analysed report
- **Sources:** AlienVault OTX · **TLP:** TLP:CLEAR · **Confidence:** 100
- **CVEs:** CVE-2015-1397, CVE-2026-4815, CVE-2026-60137, CVE-2026-63030
- **ATT&CK:** T1003.001, T1003.002, T1027, T1036.005, T1047, T1059.001, T1059.004, T1078.003, T1098.004, T1110.003, T1136.001, T1190, T1505.003, T1543.003, T1583.003, T1588.002, T1588.005, T1590.002, T1591, T1595.002
- **Malware:** Cobalt Strike - S0154, PentAGI, WSO webshell, wp2shell

CyberXero is a Russian-speaking, financially motivated Initial Access Broker operating on Dark Web forums, conducting two parallel operations: a global mass-exploitation campaign targeting WordPress, Magento and e-commerce platforms, and a directed campaign focused on Ukrainian energy and utilities organizations. The actor distinguishes itself through AI augmentation, deploying 51 specialized Claude Code agents and PentAGI integrated with Cobalt Strike. Active since July 2026, CyberXero generates revenue through access brokering, payment data theft, and cryptocurrency payments. Over 40 organizations across Ukraine, Poland, China, Pakistan and the Netherlands have been affected, with more tha

## IOC appendix (defanged)

| Finding | Type | Indicator |
|---|---|---|
| F1 | domain | `juanwangccbotgithubgithub[.]com` |
| F1 | ipv4 | `14.47.118[.]194` |
| F1 | ipv4 | `190.114.197[.]2` |
| F1 | ipv4 | `46.39.24[.]98` |
| F2 | sha256 | `10d83c1748895361e07320f68d44d427b43cadd2cbffe0ab5e607ab03aec83da` |
| F2 | sha256 | `121f2050e3c891b29565fd73451fff7ae60199c86eb8d79ec1eb1d9844578487` |
| F2 | sha256 | `284e5ec8748f99fd1b8c331b699a5fe5fd4448bbaae0347a940f427f931c4d14` |
| F2 | sha256 | `2ed54e0f988a62039abed88f6394eb1e3d5ed931f0183556055417fb08844ecf` |
| F2 | sha256 | `48962b3893f2c8261e32e6b95ea7d463d145a529a8b2a6c987dd979454405c73` |
| F2 | sha256 | `48f9b72ce72ab7087794650d6eef10135345088384fbde1482f1c74a02b80302` |
| F2 | sha256 | `4fbd61cb9181ebbc4fe9a6e59d3c346dc00001da48d66bd890556fc6fad22b07` |
| F2 | sha256 | `5c4e263546fb21f8fe8732789a5b6583eaa8ae11ebeef099462a7c9bf50e022d` |
| F2 | sha256 | `6581bf37184bb2db899b9893064d39dd314ea691adf3281cc0aa7e0a31e5138a` |
| F2 | sha256 | `76692a23abe718b93e63edefd743971ec627c0cdf3778f856bd5ec88003deaa2` |
| F2 | sha256 | `9391c6ad17aced1142607c0c623b18d86a7697cc483d204ffac94093e26b8068` |
| F2 | sha256 | `a297eddfa7abea8d411afc0f150f8f6f30e470a77204de87e3b0815fa9bb8a84` |
| F2 | sha256 | `b90640b392827b4f2d280f6cf67860862953331917d42df23e1653a92f2f98ad` |
| F2 | sha256 | `c0d8ffebfba969b1c1ca76bd9623bb623e9f95155c8ceca77d8fcc521435a497` |
| F2 | sha256 | `c1d8e2829ea63b9dc1cf2c3421a5093406adad4d6622e238376e78e908e0e6e8` |
| F2 | sha256 | `dc892f5013edb0aa1e61e808511387373d8d120348b5be0929621d21e6e9946a` |
| F2 | sha256 | `dfba6008a2c828a9cb62342aec53006ae05a60cb8d4c41c3fa216fd727e8c6a3` |
| F2 | sha256 | `e4d12208789f36efc5a1ff765088fed95d6bb5972d1a804a4536fd42366797d4` |
| F2 | sha256 | `e6e113783356446aef66e5296db45b244f318292af7cebc2a9bd76f095a95c4c` |
| F2 | sha256 | `ec199c78c11040fd3127887222fd75a85e5797bf96aa691a117fdd83dd663d81` |
| F2 | sha256 | `f49f45303cbfccee14ff193ac9608f860e6d616f08c0ecbef1ec44f7c863d7ec` |
| F2 | sha256 | `3a6927a3399f2a10bb2e2229482e5096e5f1c3401a87f7f1730db11243531e28` |
| F2 | sha256 | `90d738a8d650e3fefda9d7efa4baa11bd89ab05fcf0eb173e04aa01a52b465e2` |
| F2 | ipv4 | `130.12.180[.]89` |
| F2 | ipv4 | `130.94.67[.]235` |
| F2 | ipv4 | `198.41.83[.]165` |
| F2 | ipv4 | `198.41.83[.]174` |
| F2 | ipv4 | `2.59.133[.]151` |
| F2 | ipv4 | `23.27.25[.]75` |
| F2 | ipv4 | `38.60.136[.]217` |
| F2 | ipv4 | `45.39.190[.]176` |
| F2 | ipv4 | `96.126.130[.]81` |
| F2 | sha256 | `1c93ea48fa7ff886a6d81e44869dd7962309e95d01c1561df362b0b18007a562` |
| F2 | sha256 | `2d692ee6dcb41c249c55881897b7dec0550b92963e07fccdb11ad655601977c3` |
| F2 | sha256 | `4a1502affa36d106d5374bf02cf777956eef651176ec8964b26ff90f103dd506` |
| F2 | sha256 | `535b9e298defd3449ba2b10b9828925d3ce344872dcbd9470c0e8db20f0aae83` |
| F2 | sha256 | `5e99d6023dce9bb18d845a37fcdbc7ea574fdb20ab8d888ec54c695382d46036` |
| F2 | sha256 | `66bcbc8c2b9d847a1e976e57972e10eac98e9b894cbf30510bff1e8d63efb81f` |
| F2 | sha256 | `6f84cc354b785157983efa8f4b674d2e1d6c3331017f29ff8d51bc43668d4b0f` |
| F2 | sha256 | `9c15dc5a510bf2e8a16c846e61fa35c50ef733b72d4e47b6e8307498a398443c` |
| F3 | domain | `attacker-collector[.]com` |
| F3 | ipv4 | `112.121.185[.]218` |
| F3 | ipv4 | `156.240.109[.]26` |
| F3 | ipv4 | `202.160.76[.]153` |
| F3 | ipv4 | `202.160.76[.]154` |
| F3 | ipv4 | `202.160.76[.]155` |
| F3 | ipv4 | `202.160.76[.]156` |
| F3 | ipv4 | `202.160.76[.]157` |
| F3 | ipv4 | `202.160.76[.]174` |
| F3 | ipv4 | `49.158.237[.]136` |
| F7 | domain | `fastcdn[.]bar` |
| F7 | ipv4 | `104.234.26[.]163` |
| F7 | sha256 | `61c0810a23580cf492a6ba4f7654566108331e7a4134c968c2d6a05261b2d8a1` |
| F8 | ipv4 | `212.193.31[.]189` |
| F8 | sha256 | `59c535f47ab4d35f6d9fc8b8aec4a72438ea0b89e5a4dcea74b05d2d32cfa483` |
| F8 | sha256 | `71e21094c1ac1cf0275c91ed377965e248bca1c12711f6dd20e2682681fc1192` |
| F8 | sha256 | `92a789444708fa1cb4cc5a89e0aa6cc7a279b62a7b8a4d2857255a18197d0090` |
| F8 | sha256 | `a5ae0aab352871bc0b038b3aa43b03eb223425628c884af7b9fc592cd34eb86c` |

## Sources
- AlienVault OTX
- CISA KEV
- HexBrief
- hxxps://blog\[.\]polyswarm\[.\]io/yoba-malware-campaign-abuses-signed-ai-applications-to-evade-detection
- hxxps://hunt\[.\]io/blog/php2shell-honeypot-shells-root-palo-alto-firewalls
- hxxps://nvd\[.\]nist\[.\]gov/vuln/detail/CVE-2026-114713
- hxxps://nvd\[.\]nist\[.\]gov/vuln/detail/CVE-2026-123039
- hxxps://otx\[.\]alienvault\[.\]com/pulse/6ac368846173b592a85473db
- hxxps://otx\[.\]alienvault\[.\]com/pulse/6ac4285a7c6e1cd492e8b2cf
- hxxps://otx\[.\]alienvault\[.\]com/pulse/6ac5f1632c72bc95740deede
- hxxps://otx\[.\]alienvault\[.\]com/pulse/6ae4c9f97b4e07a268c06b96
- hxxps://otx\[.\]alienvault\[.\]com/pulse/6ae86a19eabc583f87c50fd6
- hxxps://otx\[.\]alienvault\[.\]com/pulse/6ae9eb16f9bae7d0faed8d7a
- hxxps://otx\[.\]alienvault\[.\]com/pulse/6aeae4fe1c423d6e45143b77
- hxxps://otx\[.\]alienvault\[.\]com/pulse/6aeb40b4e681d29bd1496aac
- hxxps://otx\[.\]alienvault\[.\]com/pulse/6aec5fe9d7ff10f7065a9f18
- hxxps://otx\[.\]alienvault\[.\]com/pulse/6aed32c8b1c53b811aaa8bb0
- hxxps://otx\[.\]alienvault\[.\]com/pulse/6aedb6df481d077141e5e5e4
- hxxps://otx\[.\]alienvault\[.\]com/pulse/6af327a10b5317aadf0fbfc8
- hxxps://securelist\[.\]com/storm-2603-fileless-toolshell-attack/121467/
- hxxps://securelist\[.\]com/tr/cyberstrikeai-attacks/121715/
- hxxps://securityscorecard\[.\]com/blog/a-dish-served-lukewarm-the-refrigerator-botnet/
- hxxps://socradar\[.\]io/blog/dark-web-profile-cyberxero/
- hxxps://socradar\[.\]io/blog/keyhunter-operation-harvard-alumni-stanford-llm-key-data/
- hxxps://www\[.\]acronis\[.\]com/en/tru/posts/bossai-inside-the-ai-attack-mesh-that-targeted-taiwans-emergency-services/
- hxxps://www\[.\]esentire\[.\]com/blog/remcos-rat
- hxxps://www\[.\]f5\[.\]com/labs/articles/attackers-target-ai-development-platform-langflow
- hxxps://www\[.\]fortinet\[.\]com/blog/threat-research/clingstun-linux-backdoor-abuses-public-stun-infrastructure
- hxxps://www\[.\]nozominetworks\[.\]com/blog/a-stunning-disguise-cling-malware-masquerades-as-google-

## Method

Narrative written by a local AI model; every fact is checked against cited sources.
Ranking is rule-based (`scoring.py`): KEV, exploitation, recency, independent sources, confidence, education/Malaysia/ASEAN relevance, and warninglist hits. 40 lower-ranked findings are listed in `brief.json`.
