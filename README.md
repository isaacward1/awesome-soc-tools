# awesome-soc-tools
A collection of free threat intelligence and enrichment tools for SOC triage

🍒 - tool requires an account for useful/full functionality

**👉 [Bookmarks.html]() for browser import**

<br>

## General
[CyberChef](https://gchq.github.io/CyberChef/) - de(en)coding, parsing and data extraction, text transformation, etc.

[VirusTotal](https://www.virustotal.com/gui/home/upload) - file/url scanning, multi-AV detection, contextualization, community insight

[OTX AlienVault](https://otx.alienvault.com/browse/global/pulses?include_inactive=0&sort=-modified&page=1&limit=10) - community-driven threat intel, threat feeds, IOC correlation

[ThreatFox](https://threatfox.abuse.ch/browse/) - huge IOC database, malware C2 domains/IPs, real-time threat data

[URLhaus](https://urlhaus.abuse.ch/browse/) - active malware URL feeds, payload hosting, takedown tracking

[AbuseIPDB](https://www.abuseipdb.com/) - IP reputation checks, abuse reports, community-driven blacklisting

[IOC Radar](https://socradar.io/labs/app/ioc-radar) - IOC aggregation, severity score, MITRE and threat tags, AI insight

[ThreatBook CTI](https://i.threatbook.io/research) - APT and campaign association, AI summary, related files

[SecureFeed](https://www.securefeed.com/) - real-time feed aggregation, tagging, automated enrichment

[GreyNoise](https://viz.greynoise.io/) - host reputation/behavior, trust level score, timeline 🍒

[Criminal IP](https://www.criminalip.io/) - IP/domain risk scoring, open port enumeration, historical info

[Talos Intelligence](https://talosintelligence.com/) - threat reputation, block list search, subnet correlation

[IBM X-Force Exchange](https://exchange.xforce.ibmcloud.com/) - risk score, categorization, host timeline, passive DNS

[SecurityTrails](https://securitytrails.com/app/account) - Historical DNS records, subdomains 🍒

[ThreatMiner](https://www.threatminer.org/index.php) - IOC search, passive DNS, malware/URL association

[MalwareURL](https://www.malwareurl.com/) - URL/IP/domain reputation check

[Pulsedive](https://pulsedive.com/dashboard/) - threat indicator enrichment, risk scoring, feed integration

[CTX](https://www.ctx.io/) - real-time threat collaboration, communicating files, APT intelligence 🍒

[CrowdSec CTI](https://app.crowdsec.net/cti) - community reporting on malicious IP activity 🍒

[InQuest Labs](https://labs.inquest.net/) - IP/domain/hash search, sometimes cracked, most times trash

<br>

## Malware Analysis
[MalwareBazaar](https://bazaar.abuse.ch/browse/) - malware sample repository, hash/tag search, file info, multi-vendor integration

[ANY.RUN](https://app.any.run/) - interactive sandbox, real-time malware behavior, network analysis 🍒

[Hybrid Analysis](https://www.hybrid-analysis.com/) - sandbox report search, static/dynamic file analysis, Falcon Sandbox integration

[MetaDefender](https://metadefender.com/) - multi-engine file scanning, metadata extraction, threat checks

[Filescan.io](https://www.filescan.io/scan) - cloud sandboxing, behavioral analysis, IOC extraction

[Joe Sandbox](https://www.joesandbox.com/#windows) - deep sandbox reports, static/dynamic/code analysis 🍒

[Kaspersky Opentip](https://opentip.kaspersky.com/requests?tab=upload) - hash/domain/file lookups, Kaspersky verdicts

[Threat.Zone](https://app.threat.zone/scan) - file/URL analysis, AV engines, behavior report export

[Threat.Rip](https://threat.rip/) - IOC search engine, IP/domain/file enrichment, OSINT aggregation

[Recorded Future Triage](https://tria.ge/s) - malware sandbox analysis, auto-tagging, IOC extraction

[VirusSign](https://www.virussign.com/malware-scan/) - file scanning, malware hash lookup, sandbox results

[VMRay Threat Feed](https://threatfeed.vmray.com/) -  live malware scan feeds, hash/URL report search, YARA matches

[PolySwarm](https://polyswarm.network/) - multi-engine scanning, threat scoring, threat market integration

[CyberFortress Threat List](https://cyber-fortress.com/threat-list/) - curated IOC lists, malware hashes, indicators

[JaffaCakes118](https://jaffacakes118.dev/analysis/) - random guy’s filescan website

[Valkyrie Verdict](https://verdict.valkyrie.comodo.com/) -  file analysis, cloud sandboxing, automated verdict engine

[GridinSoft Malware Check](https://gridinsoft.com/online-virus-scanner) - quick malware scans, file reputation

[Dr.Web](https://vms.drweb.com/) - static file scanning, AV detection, Dr.Web threat insights

[Docguard](https://www.docguard.io/) - document threat detection, macro analysis, static + behavioral checks

[Cuckoo Sandbox](https://cuckoo.cert.ee/dashboard/) - not maintained, demo instance of Cuckoo Sandbox, long scan queue

[CAPEv2 Search](https://capesandbox.com/analysis/search/) - hash search, file upload, behavioral/network analysis

<br>

## Webpage Analysis
[urlscan.io](https://urlscan.io/) - scans and screenshots URLs, captures page structure, passive DNS, IOC extraction

[curl Online](https://reqbin.com/curl) - test HTTP requests (GET, POST, etc.), view headers/responses, webpage preview

[Wayback Machine](https://web.archive.org/) - view archived versions of websites, check defacements/changes

[Wappalyzer](https://www.wappalyzer.com/) - website technology stack profiler 🍒

[BuiltWith](https://builtwith.com/) - another website technology stack profiler

[urlquery.net](https://urlquery.net/) - analyze URL behavior, detect redirects, extract IOCs

[Cloudflare Radar](https://radar.cloudflare.com/scan) - Cloudflare’s verdict, screenshot, HTTP transactions, HTML source, indicators

[CheckPhish](https://checkphish.bolster.ai/) - detect phishing pages, expand URLs, screenshot, check redirection

[URLVoid](https://www.urlvoid.com/) -  URL/domain reputation, blacklist check, basic metadata

[urlDNA](https://urldna.io/) - scan verdict, webpage fingerprinting, similarity analysis, HTTP transaction events

[Browserling](https://www.browserling.com/) - live 3-min interactive browser testing, safe link viewing

[Wannabrowser](https://www.wannabrowser.net/) - test GET/POSTs, different User-Agents, headers, HTML source

[URL2PNG](https://www.url2png.com/) - generate real-time screenshots of webpages

[Sucuri SiteCheck](https://sitecheck.sucuri.net/) - malware scanner for websites, blacklist status, security headers

[FortiGuard Web Filter](https://fortiguard.fortinet.com/webfilter) - URL category lookup, threat reputation check

[deobfuscate.io](https://deobfuscate.io/) - good JavaScript deobfuscator

[de4js](https://lelinhtinh.github.io/de4js/) - another good JavaScript deobfuscator

[ExpandURL](https://www.expandurl.net/) - expands a shortened URL

<br>

## DNS/IP Lookup
[CentralOps.net](https://centralops.net/co/) - whois, AS info, DNS records, traceroute, network diagnostics

[Whoisfreaks](https://whoisfreaks.com/) - whois/DNS records search tools

[Whois.com](https://www.whois.com/whois/) - another whois tool; domain/IP whois lookups, registrar and ownership info

[ViewDNS.info](https://viewdns.info/) - whois, DNS records, reverse IP, ASN and geolocation tools

[DNSDumpster](https://dnsdumpster.com/) - DNS records and mapping, subdomain discovery, network recon

[IPVoid](https://www.ipvoid.com/) - IP blacklist check, whois, ping, networking tools, etc.

<br>

## Internet Asset Recon
[Censys](https://search.censys.io/) - DNS/routing info, service fingerprinting, certificates, open ports

[Netify](https://www.netify.ai/resources/ips) - IP/hostname technology stack (platform/app/network), public bot/web scraper list

[Shodan](https://www.shodan.io/search/advanced) - search exposed devices; subdomains and related IPs, services, banners, vulnerabilities

[FOFA](https://en.fofa.info/) - asset protocol/service fingerprinting, JARM/JA3/body_hash search, Chinese internet visibility? (dont click the hyperlinks above search results 🤦‍♂️)

[ZoomEye](https://www.zoomeye.ai/) - basically FOFA, another host search engine, built on XMap 🍒

[Netlas](https://app.netlas.io/) - search for hosts by server response/banners, WHOIS/DNS records, cert info, etc. 🍒

[ONYPHE](https://search.onyphe.io/) - HTML source, certificate info, many categories

<br>

## Other
[EveBox](https://rules.evebox.org/search) - IDS/IPS rule search, ruleset catalog, rule changelog

[OUI Lookup](https://www.wireshark.org/tools/oui-lookup.html) - search OUI of MAC address for vendor information. Supports all formats.

[crt.sh](https://crt.sh/) - lookup domain SSL/TLS certificate history

[GCK Filesig Search](https://filesig.search.org/) - identify files via headers/trailers 

[VirusTotal Sources](https://docs.virustotal.com/docs/contributors) - scanning engines, sandboxes, repositories, and datasets used by VirusTotal

[hslatman/awesome-threat-intelligence](https://github.com/hslatman/awesome-threat-intelligence) - curated list of threat intel tools, feeds, APIs, and platforms

[rshipp/awesome-malware-analysis](https://github.com/rshipp/awesome-malware-analysis) - resources for static/dynamic malware analysis, online sandboxes, reversing engineering, etc.

[0x4D31/awesome-threat-detection](https://github.com/0x4D31/awesome-threat-detection) - curated list of threat detection and hunting resources, rules, and frameworks

<br>
