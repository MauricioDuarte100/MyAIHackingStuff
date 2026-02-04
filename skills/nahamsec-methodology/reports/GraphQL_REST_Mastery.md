# Manual Maestro: GraphQL & REST API Hacking

Based on the provided sources, there is **no mention** of a specific Studio Artifact or document titled **"Manual Maestro: Hacking Avanzado de GraphQL y APIs RESTful."**

However, the sources contain extensive information regarding the **advanced hacking of GraphQL and REST APIs**, primarily from presentations by researchers such as **0xlupin**, **InsiderPhD**, **NahamSec**, and **Katie Paxton-Fear**. Below is a detailed compilation of the advanced techniques and methodologies for both GraphQL and REST APIs found within the transcripts.

### **1. Advanced GraphQL Hacking**
According to the presentation "GraphQL is the New PHP" by 0xlupin and various CTF walkthroughs, the following techniques are essential for attacking GraphQL endpoints:

#### **Reconnaissance and Schema Discovery**
*   **Identification:** You can identify GraphQL endpoints by looking for JSON bodies containing `query` or `mutation` fields, or GET requests with a `query` parameter [1].
*   **Introspection:** The first step is checking if Introspection is enabled, which functions like a self-updating Swagger file, describing all available data, operations, and mutations [2].
*   **Bypassing Disabled Introspection:**
    *   **Field Suggestion Fuzzing:** If introspection is disabled, the server may still offer "Did you mean..." suggestions when invalid fields are sent. Tools like **Clairvoyance** can fuzz these suggestions to reconstruct the schema recursively [3, 4].
    *   **JavaScript Analysis:** Tools like **J-Whizzle** (commercial) or **J-Loose** (open source) can parse JavaScript files to find queries and mutations already present in the frontend code to generate a wordlist for fuzzing [5].

#### **Vulnerability Classes and Exploits**
*   **Authorization Bypasses (Nested Queries):** Security rules might apply to top-level queries (e.g., `credit_card`) but not to nested objects. An attacker might access sensitive data (e.g., credit card balance) by traversing through a different parent object (e.g., `organization -> account -> balance`) [6, 7].
*   **WAF Bypass via WebSockets:** Some WAFs block malicious JSON in HTTP POST requests but fail to inspect WebSocket traffic. If the GraphQL server accepts queries over WebSockets, attackers can bypass filters [8].
*   **Cross-Site WebSocket Hijacking (CSWSH):** If authentication is solely cookie-based and lacks CSRF tokens during the WebSocket handshake, attackers can initiate a malicious WebSocket connection from a victim's browser to perform mutations (e.g., declining an invitation) [9, 10].
*   **DoS and Batching (XS-Search):**
    *   GraphQL allows **Aliasing**, which lets an attacker request the same operation multiple times in a single request (e.g., repeating a search query 100 times).
    *   This can induce a massive delay (DoS). By measuring the time difference between a query that returns data (slow) and one that doesn't (fast), attackers can perform **XS-Search** (Cross-Site Search) to exfiltrate data boolean-style [11, 12].

### **2. Advanced REST API Hacking**
The sources detail methodologies for discovering and exploiting REST APIs, focusing on logic flaws and improper authorization.

#### **Discovery and Mapping**
*   **Documentation Hunting:** Search for **Swagger/OpenAPI** specifications (e.g., `swagger.json`, `api-docs`) to map out the entire API structure [13, 14]. Tools like **Swagger Jacker** can automate the detection of these files and even identifying broken authentication in them [15].
*   **Version Fuzzing:** Always check for different API versions (e.g., changing `/v1/` to `/v2/` or `/v3/`). Newer or older versions might lack security controls present in the current production version [16].
*   **Traffic Analysis:** Use a proxy (Burp Suite/Kaido) to analyze traffic. Pay attention to `POST`, `PUT`, and `DELETE` methods, not just `GET` [17].

#### **Vulnerability Classes and Exploits**
*   **Mass Assignment:**
    *   Modern frameworks often bind user input directly to database objects.
    *   Attackers can guess fields like `is_admin`, `role`, or `balance` and inject them into a request (e.g., registration or profile update) to elevate privileges. For example, changing a user role from "user" to "admin" or "staff" by adding `"role": "admin"` to the JSON body [18, 19].
*   **BOLA / IDOR:**
    *   Test if you can access or modify another user's resources by changing IDs (integers or UUIDs) in the URL or body.
    *   **Pro Tip:** If an API endpoint requires an ID (e.g., `/users/123/tickets`), try accessing it via a different parent resource or method (e.g., `POST` vs `GET`) to see if authorization checks are missing [20, 21].
*   **Content-Type Spoofing:** If an API expects JSON but returns a response with `Content-Type: text/html`, you may be able to inject HTML/JavaScript to achieve XSS, as the browser will render the response [22, 23].
*   **Authentication Bypass:**
    *   Attempt to access endpoints by removing the authentication token entirely (testing for unauthenticated access) [24].
    *   Use header injection (e.g., `X-Forwarded-For: 127.0.0.1`) to bypass IP-based restrictions on internal administrative endpoints [25].

### **Recommended Resources Mentioned**
The sources explicitly recommend specific books for mastering these topics:
1.  **"Black Hat GraphQL"** by Nick Aleks and Dolev Farhi: Recommended for deep diving into GraphQL attacks [26, 27].
2.  **"Hacking APIs"** by Corey Ball: Recommended for a comprehensive guide on breaking web application APIs [28].