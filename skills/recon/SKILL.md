---
name: Reconnaissance & Attack Surface Mapping
description: This skill provides a comprehensive methodology for mapping a target's attack surface, starting from a company name to a complete list of live assets. It covers passive discovery, DNS resolution, active brute-forcing, permutation analysis, root domain discovery, and public exposure probing.
metadata:
  author: Apex
  version: "1.0"
---

# Reconnaissance & Attack Surface Mapping

## Purpose
Gather the complete blueprint of a target before any active attacking. This methodology focuses on finding forgotten assets, mapping hidden subdomains, and identifying live services.

## Inputs
- Company Name / Root Domain
- (Optional) DNS Wordlists
- (Optional) Fast Resolvers list

## Core Workflow

### Phase 1: Passive DNS Discovery
Query public databases (CT logs, search engines, DNS caches).
- **Tool**: `subfinder`
- **Action**: `subfinder -d example.com -o passive-subdomains.txt`

### Phase 2: DNS Resolution
Filter out non-resolving domains to focus on live targets.
- **Tool**: `puredns`
- **Action**: `cat passive-subdomains.txt | puredns resolve | tee resolved.txt`

### Phase 3: Active DNS Discovery
Find subdomains not indexed by passive sources.

#### 3.1 DNS Brute-Forcing
- **Tool**: `puredns`
- **Action**: `puredns bruteforce wordlist.txt example.com -r resolvers.txt -w bruteforce-results.txt`

#### 3.2 DNS Permutations
Generate and test intelligent variations.
- **Tool**: `alterx`
- **Action**: `cat passive-subdomains.txt | alterx | puredns resolve | tee permutations.txt`

### Phase 4: Root Domain Discovery
Expand scope beyond the main domain.
- **Acquisitions**: Check Crunchbase or similar.
- **Reverse WHOIS**: Use tools like `whoxy.com` or `whois` queries for registrant organization.
- **Creative OSINT**: Job postings, GitHub, LinkedIn, press releases.

### Phase 5: Public Exposure Probing
Analyze live assets for services, technologies, and metadata.

#### 5.1 Web Exposure
- **Tool**: `httpx`
- **Action**: `cat resolved.txt | httpx -title -status-code -ip -cname -tech-detect -o metadata.txt`

#### 5.2 Network Exposure (Non-HTTP)
- **Tool**: `nmap`
- **Action**: `nmap -sV -p- --min-rate 1000 example.com`

## Summary Checklist
- [ ] Root domains identified?
- [ ] Passive enumeration completed?
- [ ] List resolved?
- [ ] Brute-forcing/Permutations ran?
- [ ] New root domains discovered via acquisitions/WHOIS?
- [ ] Httpx metadata captured?
- [ ] Critical non-web ports scanned?

## Pro Tips
- **403 Forbidden**: Don't ignore them. Use `dirsearch` or `ffuf` to find accessible paths like `/api`, `/admin`, or `/backup`.
- **Vertical & Horizontal**: Always look for horizontal expansion (new roots) before deep vertical diving.
- **Automation**: Chain these tools into single-line pipelines for speed.
