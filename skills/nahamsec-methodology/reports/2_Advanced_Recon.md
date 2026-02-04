# Advanced Reconnaissance & Shadow IT

## 1. Deep Asset Discovery


{"status":"success","answer":"Here is a deep technical dive into **Relentless Reconnaissance**, synthesizing advanced workflows and syntax from the provided sources.\n\n### 1. Advanced Tooling Syntax & Configuration\nEffective reconnaissance requires moving beyond default settings to maximize asset discovery through aggressive enumeration and permutation.\n\n**Amass (The Engine)**\nAmass should be treated as an ecosystem, not just a scanner. It uses a cyclic process where findings from one source feed others.\n*   **Intelligence Mode (Horizontal):** Map the target's IP space and root domains using ASN.\n    ```bash\n    amass intel -asn [ASN_NUMBER] -whois -d [ROOT_DOMAIN]\n    ```\n*   **Enumeration Mode (Vertical):** For deep subdomain discovery.\n    *   **Active Mode:** Enables direct interaction (certificate pulling, zone transfers) rather than just passive scraping [1].\n    *   **Brute-Forcing:** Enable recursive brute-forcing to find nested subdomains (e.g., `dev.api.target.com`).\n    *   **Config File:** Crucial for API keys and resolver limits. Jeff Foley recommends increasing the resolver count significantly (e.g., using `dnsvalidator` to generate a list of 9,000+ resolvers) and tuning `-max-dns-queries` to around 20,000 for high performance [2], [3].\n    ```bash\n    amass enum -active -d target.com -brute -w [WORDLIST] -rf resolvers.txt -config config.ini\n    ```\n*   **Scripting Engine:** You can write custom Lua scripts (saved as `.eds`) to introduce new data sources or wrap external tools (like `assetfinder`) directly into the Amass engine [4], [5].\n\n**Subfinder & Chaos**\nSubfinder is optimized for speed and passive sources.\n*   **Configuration:** Always configure the `provider-config.yaml` with API keys (e.g., SecurityTrails, GitHub, Chaos) to unlock deep data that isn't available anonymously [6], [7].\n*   **Syntax:**\n    ```bash\n    subfinder -d target.com -all -config config.yaml -silent\n    ```\n\n**MassDNS & ShuffleDNS**\nMassDNS is the backbone for high-speed resolution, often wrapped by **ShuffleDNS** for easier handling of wildcards and wordlists.\n*   **Workflow:** Generate a massive list of potential subdomains using permutations, then pipe to ShuffleDNS to resolve them against a list of trusted resolvers.\n*   **ShuffleDNS Syntax:**\n    ```bash\n    shuffledns -d target.com -w [WORDLIST] -r resolvers.txt -mode bruteforce\n    ```\n    *   *Note:* This handles wildcard filtering automatically, which is critical when brute-forcing large targets [8].\n\n**PureDNS / DNSx**\nUsed for cleaning and validating data sets.\n*   **DNSx:** Can be used to check liveness (A records) and probe for CNAMEs (useful for subdomain takeovers) [9].\n    ```bash\n    cat subdomains.txt | dnsx -resp -a -cname -silent\n    ```\n\n---\n\n#

## 2. Google & GitHub Dorks (Manual)


**Google Dorks**
*   **Site Filtering:**
    *   `site:target.com -www`: Excludes the main `www` subdomain to find other assets [1].
    *   `site:target.com -site:www.target.com`: Another variation to exclude specific subdomains [2].
    *   `site:target.com inurl:api`: Identifies API endpoints within the target domain [1].
    *   `site:target.com inurl:login`: Locates login pages [3].
*   **Keyword & Title Searches:**
    *   `intitle:"dashboard"`: Looks for pages with "dashboard" in the title [3].
    *   `intitle:"index of"`: Searches for directory listings [4].
    *   `inurl:admin` or `intitle:admin`: Searches for administrative panels [5].
    *   `intitle:"setup"`: Searches for installation or setup documentation [6].
*   **File Types & Extensions:**
    *   `filetype:php`, `filetype:xls`, `filetype:pdf`, `ext:php`: Searches for specific file extensions that might leak information [7], [6].
    *   `inurl:xls`, `inurl:pdf`: alternate syntax for finding specific file types in the URL [6].
*   **Parameter Finding:**
    *   `inurl:&`: Searches for URLs containing the ampersand, indicating multiple parameters which are useful for fuzzing [8].
    *   `inurl:http` or `inurl:url`: Searches for parameters that might take a URL, useful for SSRF [9].
*   **Legal & Policy Text:**
    *   Searching for specific strings from a company's privacy policy, terms of service, or copyright text (e.g., `"copyright 2019 twitch interactive"`) to find related domains [10].

**GitHub Dorks**
*   **Sensitive Files & Configurations:**
    *   `filename:.npmrc`, `filename:.dockercfg`, `filename:config.yaml`: Searches for configuration files that often contain secrets [11].
    *   `filename:vim_settings.xml`: Searches for IDE configuration files [12].
    *   `path:config.yaml`: Searches specifically within the file path [11].
    *   `extension:json api_key`: Searches for JSON files containing "api_key" [13].
*   **Credentials & Secrets:**
    *   `"password"`, `"docker config"`, `"PEM private"`, `"s3cfg"`, `"secret"`: Keywords combined with a target domain to find leaked credentials [14].
    *   `"Authorization: Bearer"`: Searches for hardcoded bearer tokens [15].
    *   `"api_key"`, `"client_secret"`: Searches for API keys and secrets [13], [15].
*   **Infrastructure & Endpoints:**
    *   `"target.com" "internal"`: Searches for internal domains or references [16].
    *   `org:targetname "string"`: Scans a specific organization's repositories for a string [17].
    *   `"dev.target.com"`, `"stg.target.com"`, `"test.target.com"`: Searches for development or staging environments [18].
    *   `regex:^api`: Using regular expressions to find repositories or files starting with "api" [13].


