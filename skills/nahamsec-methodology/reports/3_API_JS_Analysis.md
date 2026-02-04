# JavaScript Analysis & API Hacking

## 1. Static & Dynamic Analysis


{"status":"success","answer":"Based on the provided transcripts, here is the methodology for extracting hidden value from JavaScript and APIs, ranging from static analysis to advanced fuzzing strategies.\n\n### 1. JavaScript Analysis: Manual vs. Automated\n\nThe most effective approach combines both manual and automated analysis to uncover endpoints, logic, and secrets.\n\n**Automated Static Analysis**\nAutomation is best used for broad discovery and initial parsing.\n*   **Purpose:** To quickly extract endpoints, links, and variable names from large sets of JavaScript files without reading every line [1].\n*   **Limitations:** Automated tools can lack context. They might find an endpoint but won't tell you *how* it interacts with the application or what parameters are required [2, 3].\n*   **Technique:** Use tools to \"beautify\" or \"un-minify\" code first, then run parsers to strip out URLs and relative paths [4].\n\n**Manual Static Analysis**\nManual review is critical for understanding business logic and finding complex bugs.\n*   **Methodology:** Read the code to understand the \"sources\" (inputs) and \"sinks\" (where data executes) [5].\n*   **Targeted Approach:** Instead of reading everything, use browser DevTools to search for specific keywords like `api`, `v1`, `post`, or `get` within the loaded JS files [6, 7].\n*   **The \"Renniepak\" Method:** A highly recommended manual/hybrid technique involves using a custom browser bookmarklet to extract all endpoints from the *current* page's JavaScript context. This results in more focused testing data than blind scraping [8-10].\n*   **Developer Comments:** manually look for comments like `// TODO`, `FIXME`, or notes about \"internal\" endpoints, as developers often leave clues about future or hidden features [11].\n\n### 2. Grep and Regex Patterns for Secrets and Endpoints\n\nUsing `grep` or specialized tools to hunt for specific patterns is standard practice for finding leaks.\n\n**Key Patterns to Search:**\n*   **API Routes:** Search for `API/`, `v1/`, `v2/`, `graphql`, or `swagger` to find hidden routes [12-14].\n*   **Sensitive Keywords:** Grep for terms like `access_key`, `secret`, `token`, `authorization`, `bearer`, and `password` [15-17].\n*   **Cloud Keys:**\n    *   **AWS:** Look for `AKIA` followed by alphanumeric characters [18].\n    *   **Google Cloud (GCP):** Use regex for keys starting with `AIza` followed by 35 characters (alphanumeric, dashes, underscores) [18].\n*   **Parameters:** Search for `var [name] =` or `const [name] =` to identify variable assignments that might control application logic or feature flags [19].\n\n**Tooling for Patterns:**\n*   **GF (Grep Fuzz):** A wrapper around grep that allows you to use pre-defined pattern files (e.g., for AWS keys or potential XSS sinks) against a large list of files or URLs [20].\n\n#

## 2. Specific Grep Patterns


**Codebase & File Searching (Grep/Ctrl+F)**
*   **Endpoint Discovery:**
    *   Search for `api`, `v1`, `v2`, `v3`, `graphql`, `swagger`, `api-docs` to find API routes and documentation [42], [43], [44].
    *   Search for `admin`, `dashboard`, `internal`, `staff`, `backoffice` to find privileged areas [45], [46].
*   **Vulnerability Indicators:**
    *   Search for `reset password`, `return_url`, `redirect_uri`, `cancel_url`, `next` to find open redirect or business logic flaws in authentication flows [47], [48], [49].
    *   Search for `postMessage` in JavaScript files to identify client-side communication that may be vulnerable to DOM XSS [50].
    *   Search for error messages found in the browser within the source code to locate the exact file or function handling the error [47].
    *   Search for `dangerouslySetInnerHTML` or `eval()` in JavaScript to find XSS sinks [51].
*   **Infrastructure & Secrets:**
    *   Search for `CI`, `Jenkins`, `GitLab`, `Jira`, `Grafana`, `Kibana` within subdomain lists to identify internal tools [52], [53].
    *   Search for `Authorization`, `Bearer`, `Token`, `key` within JavaScript files to find hardcoded credentials [15].

**Command Line & Tool-Assisted Queries**
*   **Header Analysis:**
    *   Grep for `Location` headers in response data to find open redirects or internal SSO redirects (e.g., `grep "Location: .*sso"` or `grep "Location: .*okta"`) [54].
    *   Grep for `X-Forwarded-For` or `X-Real-IP` to identify potential header injection or bypass opportunities [34].
*   **Content Discovery:**
    *   Grep for `is_admin`, `superuser`, `role` in API responses to identify mass assignment opportunities [36].
    *   Grep for `SAML`, `OneLogin`, `Okta` in headers or body to identify internal authentication portals [55].
    *   Grep for `tomcat`, `apache`, `nginx` in server headers to fingerprint backend technologies for specific CVEs [4], [56].
