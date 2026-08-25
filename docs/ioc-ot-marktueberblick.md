# IOC für OT — Marktüberblick

*Kurzüberblick: Welche IOC-/Threat-Intelligence-Quellen es für Operational Technology (OT/ICS) am Markt gibt, wofür man sie einsetzt und worauf man bei der Auswahl achtet. Stand: 2026, DACH-orientiert.*

> **TL;DR für den Kollegen:** Reine „IOC-Feeds" (IPs, Hashes, Domains) sind in OT **weniger wert als in IT** — echte OT-Angriffe sind selten und maßgeschneidert, IOCs veralten schnell. Der Hebel in OT liegt bei **verhaltens-/TTP-basierter Erkennung** (MITRE ATT&CK for ICS) und **Asset-/Protokoll-Anomalien** im passiven Netzwerk-Monitoring. IOCs sind das Add-on, nicht das Fundament. Für den Einstieg reichen **kostenlose Quellen** (CISA, MITRE, Hersteller-PSIRTs, MISP); kommerzielle OT-Intel (Dragos, Nozomi, Claroty …) lohnt sich, wenn man Betrieb/SOC in kritischer Infrastruktur betreibt.

---

## 1. Was ist ein IOC im OT-Kontext — und was nicht

**IOC (Indicator of Compromise)** = konkreter, beobachtbarer Hinweis auf eine Kompromittierung. Abzugrenzen von:

- **IOA (Indicator of Attack) / TTP** — *Verhalten* eines Angreifers (Taktiken, Techniken, Prozeduren). In OT deutlich wertvoller, weil verhaltensstabiler.
- **Vulnerability/CVE** — Schwachstelle, nicht Kompromittierung. (Für OT über Advisories/PSIRTs, siehe unten.)

### IOC-Typen, die in OT relevant sind

| Ebene | Beispiele | Für PicoCap relevant? |
|---|---|---|
| **Netzwerk** | Bösartige IP/Domain/URL, JA3/JA3S-Fingerprints, C2-Beacons, ungewöhnliche Ziel-Ports | **Ja** — aus PCAP ableitbar |
| **OT-protokollspezifisch** | Unerwartete Modbus-Funktionscodes, S7comm-`STOP`/Firmware-Upload, DNP3-/IEC-104-Steuerbefehle aus falscher Quelle, EtherNet/IP-, BACnet-Anomalien | **Ja** — PCAP + Protokoll-Dekodierung |
| **Host / Endpoint** | Datei-Hashes (SHA-256), Dateinamen, Registry-Keys, Mutexe, Service-Namen | Nein (kein Endpoint-Agent in OT üblich) |
| **Firmware/Engineering** | Manipulierte Projekt-/Ladder-Logic-Dateien, bekannte bösartige Firmware-Hashes | Teilweise |

### Warum OT anders ist

- Langlebige Systeme (10–25 Jahre), oft kein Patch, **kein AV-Agent auf SPS/PLC** → passives Monitoring statt Endpoint.
- **Wenige, aber gezielte** OT-Malware-Familien — die „Klassiker", die den Referenzrahmen bilden:
  Stuxnet · Havex/Dragonfly · BlackEnergy · **Industroyer/CrashOverride** (2016) · **TRITON/TRISIS** (Safety-System, 2017) · **Industroyer2** (2022) · **PIPEDREAM/INCONTROLLER** (2022, modulares OT-Toolkit) · **FrostyGoop/BUSTLEBERM** (2024, Modbus-basiert, Fernwärme).
- Konsequenz: IOC-Feeds allein reichen nicht — man braucht **Baseline-Kenntnis der normalen OT-Kommunikation** und TTP-Mapping.

---

## 2. Formate & Standards (Interoperabilität)

Damit IOCs zwischen Feed, TIP, SIEM und Sensor fließen:

- **STIX 2.1 / TAXII 2.1** — De-facto-Standard für strukturierten Austausch (u.a. CISA AIS).
- **MISP** — Open-Source-Plattform *und* Format zum Teilen/Korrelieren von IOCs; große Community, viele OT-relevante Feeds.
- **YARA** — Datei-/Speicher-Signaturen (Malware-Samples, Engineering-Artefakte).
- **Sigma** — generische SIEM-/Log-Detektionsregeln.
- **Snort/Suricata** & **Zeek** — netzwerkbasierte Erkennung; beide mit **ICS-Protokoll-Unterstützung** (Modbus, DNP3, ENIP/CIP, S7, BACnet, IEC 61850/104). → **Direkter Bezug zu PicoCap/PCAP.**
- **MITRE ATT&CK for ICS** — kein IOC-Feed, sondern das **TTP-Framework** zur Einordnung von OT-Angreiferverhalten (die eigentliche Grundlage für Detection-Engineering in OT).
- OpenIOC — älter, kaum noch neu genutzt.

---

## 3. Kommerzielle OT-Threat-Intelligence / IOC-Quellen

Der Kern des OT-Security-Markts. Gartner veröffentlichte im **Februar 2025 den ersten Magic Quadrant „Cyber-Physical Systems Protection Platforms"** (17 Anbieter); **Leader: Claroty, Dragos, Microsoft, Armis, Nozomi Networks**.

| Anbieter | OT-Intelligence-Angebot | Stärke / Profil |
|---|---|---|
| **Dragos** | **WorldView** (OT-Threat-Intel-Reports, IOCs, Threat Groups wie CHERNOVITE/KAMACITE), **OT Watch** (Managed Hunting) | **Tiefste OT-spezifische Intelligence**; benannte ICS-Angreifergruppen; Fokus rein OT |
| **Nozomi Networks** | Abo-basierter **Threat Intelligence Feed** (bösartige IPs/URLs, IOC-Signaturen, Malware-Hashes, TTPs), Nozomi Labs; Plattform Guardian/Vantage | Breite Sensorbasis, flexible Deployments, gutes IoT/OT-Monitoring |
| **Claroty** | **Team82** (Research + Advisories), integrierte Threat-Signaturen; Plattform xDome / CTD | Breite Asset-Abdeckung, starke IT/OT-Integration, viele PLC-Schwachstellen-Funde |
| **Microsoft** | **Defender for IoT** (ex-CyberX) + Microsoft Threat Intelligence (MSTIC) | Enge Azure/Sentinel-SIEM-Integration; im MQ als Leader |
| **Armis** | Centrix + Asset-/Threat-Intelligence | Sehr breite Asset-Discovery (IT/OT/IoT/medizinisch) |
| **Google / Mandiant** | **Google Threat Intelligence** inkl. **Mandiant** ICS/OT-Reporting | Starke IR-/APT-Attributionsdaten, auch OT-Kampagnen |
| **Recorded Future** | Threat-Intelligence-Plattform mit OT-Modul | Breite, automatisierte Sammlung, gutes Enrichment |
| **Kaspersky ICS-CERT** | ICS-Threat-Reports, IOCs, Schwachstellen-Advisories | Viel eigene OT-Malware-Forschung (Achtung: BSI-Warnung 2022 / Beschaffungsrestriktionen in DACH beachten) |
| **Tenable OT Security** (ex-Indegy) | OT-Asset- + Schwachstellen-/Threat-Daten | Stark bei Vulnerability-Management in OT |
| **Forescout** | **Vedere Labs** Research + Feeds | Gute Device-Intelligence, viele Protokoll-Studien |
| **Cisco** | **Talos** Intelligence + **Cyber Vision** (OT-Sichtbarkeit) | Großer IT-Intel-Apparat, in Cisco-Netzen integriert |
| Weitere | **TXOne**, **Darktrace/OT**, **Fortinet (FortiGuard)**, **Palo Alto (Unit 42)**, **OTORIO**, **Waterfall** | Je nach Umgebung/OEM-Nähe |

> **Einordnung:** Für reine OT-*Intelligence-Tiefe* (benannte ICS-Angreifer, OT-Malware-Analyse) ist **Dragos** die Referenz. Wer eine **Plattform** mit Monitoring + Intel aus einer Hand will, vergleicht Dragos / Nozomi / Claroty / Microsoft.

---

## 4. Kostenlose / Community-Quellen (guter Einstieg)

| Quelle | Was | Format |
|---|---|---|
| **CISA ICS Advisories** | Laufende ICS-Schwachstellen-Advisories (2025 stark Siemens/Rockwell/Schneider), teils mit IOCs/Mitigations | Web/PDF |
| **CISA KEV Catalog** | *Known Exploited Vulnerabilities* — Priorisierung real ausgenutzter CVEs | JSON/CSV |
| **CISA AIS** | *Automated Indicator Sharing* — maschinenlesbare IOCs, kostenlos | STIX/TAXII 2.1 |
| **MITRE ATT&CK for ICS** | TTP-Matrix für OT — Grundlage für Detection & Threat Hunting | JSON/STIX |
| **MISP** (+ OT-Communities) | Plattform + kuratierte Feeds zum Korrelieren/Teilen | MISP/STIX |
| **abuse.ch** (Feodo Tracker, URLhaus, ThreatFox) | Generische, aber hochwertige Netzwerk-IOCs (C2, Malware-URLs) | CSV/JSON/MISP |
| **AlienVault OTX** | Offene Community-„Pulses" mit IOCs | API/STIX |
| **Hersteller-PSIRTs** | **Siemens ProductCERT/CERT Services**, **Schneider Electric**, **Rockwell**, **ABB**, **Phoenix Contact** u.a. — Advisories + Fix-Infos für die eigene Anlagenbasis | CSAF/Web |
| **Sektor-ISACs** | E-ISAC (Strom, US), WaterISAC, Auto-ISAC etc. | Mitgliedschaft |

### DACH-spezifisch
- **DE — BSI**: CERT-Bund, **UP KRITIS**, Allianz für Cyber-Sicherheit; **NIS2**-Umsetzung → Meldepflichten/Anforderungen für KRITIS & wichtige Einrichtungen.
- **AT — ACS/CERT.at**, **Austrian Energy CERT (AEC)**, nationale NIS-Behörde.
- **CH — NCSC / GovCERT.ch**.
- **CSAF** (Common Security Advisory Framework) setzt sich bei Herstellern für maschinenlesbare Advisories durch — relevant für automatisiertes Schwachstellen-Matching gegen die eigene Asset-Liste.

---

## 5. Wofür setzt man das ein? (Use Cases)

1. **Detection / NSM** — Suricata/Zeek mit ICS-Protokollen + IOC-Feeds am OT-Netz-Sensor (passiv, SPAN/TAP). ← **hier lebt PicoCap-Datenmaterial (PCAP).**
2. **Threat Hunting** — TTP-getrieben (ATT&CK for ICS) über vorhandene OT-Telemetrie/PCAP.
3. **Incident Response / Forensik** — IOCs zum schnellen Scoping („haben wir das gesehen?"), Retro-Hunt über PCAP-Archive.
4. **Vulnerability-Priorisierung** — KEV + PSIRT + CVSS auf die reale Asset-Basis mappen (was ist ausnutzbar *und* vorhanden).
5. **SOC-Integration** — Feeds in **TIP** (MISP, OpenCTI) → SIEM/SOAR (Sentinel, Splunk) für Korrelation & Alerting.

---

## 6. Auswahlkriterien (worauf achten)

- **OT-Spezifität** — echte ICS-Intel oder nur umetikettierte IT-IOCs?
- **Protokoll-/Sektorabdeckung** — passt es zu deinen Protokollen (Modbus, DNP3, S7, IEC 61850/104, ENIP/CIP, BACnet) und deiner Branche (Energie, Wasser, Fertigung, Pharma)?
- **Aktualität & Fehlalarmrate** — frische, kuratierte IOCs statt großer, verrauschter Listen.
- **Passiv vs. aktiv** — in OT fast immer **passiv/read-only** (kein aktives Scannen produktiver Anlagen). *Passt zur PicoCap-Philosophie: nie schreiben/weiterleiten.*
- **Formate & Integrationen** — STIX/TAXII, MISP, Suricata/Zeek, SIEM-Konnektoren vorhanden?
- **DACH-Tauglichkeit** — Sprache, Support, Datenhoheit/Souveränität, NIS2-Bezug; bei einzelnen Anbietern (z.B. Kaspersky) Beschaffungs-/Compliance-Vorgaben prüfen.
- **Kostenmodell** — Feed-Abo vs. Plattform vs. Managed Service.

---

## 7. Bezug zu PicoCap

PicoCap arbeitet **read-only auf PCAP/PCAPNG** und erkennt u.a. Encapsulation-Ketten, VLAN/GRE/ERSPAN/VXLAN und SPAN-Doppelerfassung. Das ist genau die Datengrundlage, aus der **netzwerkbasierte OT-IOCs** und **Protokoll-Anomalien** gewonnen werden:

- PCAP → Suricata/Zeek (ICS-Parser) → Abgleich gegen IOC-Feeds (STIX/MISP) → SIEM.
- IOCs, die zum PCAP-Workflow passen: bösartige IPs/Domains, JA3, unerwartete OT-Funktionscodes/Steuerbefehle, C2-Beaconing, auffällige Encapsulation.
- PicoCap prüft dabei die **Qualität/Vollständigkeit** der Erfassung (z.B. SPAN TX+RX) — Voraussetzung dafür, dass Detection & IOC-Matching überhaupt verlässlich sind.

---

## 8. Empfehlung / Einstiegspfad

1. **Framework zuerst:** MITRE ATT&CK for ICS als Denk- und Detection-Raster.
2. **Kostenlos starten:** CISA (Advisories, KEV, AIS), Hersteller-PSIRTs der eigenen OEMs, MISP + abuse.ch/ThreatFox.
3. **Passiv erkennen:** OT-Netzsensor mit Suricata/Zeek (ICS-Protokolle) auf sauber erfasstem Traffic — PicoCap zur Erfassungsqualität.
4. **Bei KRITIS/Reifegrad:** kommerzielle OT-Intel evaluieren — **Dragos** (Intel-Tiefe) bzw. **Nozomi/Claroty/Microsoft** (Plattform + Feed), ggf. Managed Hunting.
5. **Operationalisieren:** IOCs in TIP (MISP/OpenCTI) → SIEM/SOAR, mit klarem Prozess für Aktualität, Freigabe (TLP) und Fehlalarm-Handling.

---

### Quellen
- [Gartner MQ / OT-Security-Vendors 2026 — Elisity](https://www.elisity.com/blog/leading-vendors-for-securing-ot-and-industrial-control-systems-in-2026)
- [OT/ICS Security 2026: Dragos vs Claroty vs Nozomi vs Defender for IoT](https://www.decryptiondigest.com/blog/ot-ics-security-platform-comparison-2026-dragos-claroty-nozomi-defender-iot)
- [Nozomi/Dragos als führende US-OT-Security-Player — MarketsandMarkets](https://www.marketsandmarkets.com/ResearchInsight/us-operational-technology-ot-security-companies.asp)
- [CISA — Automated Indicator Sharing (AIS)](https://www.cisa.gov/topics/cyber-threats-and-advisories/information-sharing/automated-indicator-sharing-ais)
- [CISA — ICS Advisories Recap 2025 (SOCRadar)](https://socradar.io/blog/cisa-industrial-control-systems-ics-advisories-2025/)
- [CISA — Information Sharing](https://www.cisa.gov/topics/cyber-threats-and-advisories/information-sharing)

*Erstellt für internen Gebrauch. Keine Herstellerempfehlung im vertrieblichen Sinn — Auswahl immer gegen konkrete Umgebung, Sektor und Compliance-Anforderungen (NIS2/KRITIS) prüfen.*
