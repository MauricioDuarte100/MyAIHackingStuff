# Manual Hacking & Business Logic Guide

## 1. Business Logic Flaws


**Financial & eCommerce Logic**
*   **Race Conditions:** Using multiple threads to transfer gift card balances or redeem points simultaneously, allowing a user to get "infinite money" or spend the same balance multiple times (e.g., the Starbucks gift card bug) [19], [20], [21].
*   **Coupon/Discount Abuse:** Applying a discount code, removing it, and applying it again, or manipulating the order of operations (applying discount *after* a price reduction) to get items for free or reduced prices [22], [23].
*   **Parameter Tampering (Price/Quantity):**
    *   Changing the quantity of an item to a negative number during checkout [24], [25].
    *   Modifying the price parameter in a request to pay less than the intended amount [26].
*   **Currency Manipulation:** Exploiting rounding errors in financial transactions or crypto exchanges [27], [28].

**Authentication & Authorization Logic**
*   **Registration Bypass:** Changing a response parameter (e.g., changing `{"success": false}` to `{"success": true}`) to bypass registration or 2FA checks [29], [30].
*   **OAuth Scope Manipulation:** Removing the `email` scope from a Facebook OAuth request to link an account without an email, potentially leading to account takeovers [31].
*   **Pre-Authentication Account Takeover:** Registering an account with a victim's email before they do (pre-account creation), or manipulating invite flows to accept invites meant for others [32].
*   **Response Manipulation (2FA/OTP):** Intercepting the response from a 2FA check and altering the boolean values or status codes (e.g., 403 to 200) to bypass the check [33], [34].

**Data & Input Handling**
*   **Mass Assignment:** Adding parameters like `is_admin`, `role`, `user_id`, or `account_id` to a registration or profile update request to escalate privileges or modify restricted fields [35], [36], [37].
*   **Cookie Injection:** Injecting cookies client-side (e.g., via CRLF or JavaScript) to force a user into a specific session or affiliate tracking ID [38], [39].
*   **IDOR (Insecure Direct Object Reference):**
    *   Changing an integer ID in a URL or API call to access another user's data [40].
    *   Wrapping an ID in an array (e.g., changing `id=123` to `id=[24]`) to bypass access controls [41], [37].



## 2. Race Conditions & Concurrency
*   **Technique:** Turbo Intruder (Burp Suite).
*   **Targets:** Coupon redemption, Fund transfers, Gift Cards.
*   **Logic:** Request 1 (Check Balance) -> Request 2 (Deduct Balance). If you send 50 requests between 1 and 2, you exploit the race.

## 3. IDOR Escalation Logic
*   **Swap IDs:** Change `id=123` to `id=124`.
*   **Parameter Pollution:** `id=124&id=123`.
*   **Array Wrapping:** `{ "id": [123] }` or `id[]=123`.
*   **Method Swapping:** GET blocked? Try POST/PUT/DELETE.
