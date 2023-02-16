# Table of References

Well this is a repo that I use for creating/reporting issues to clients during day2day works and maybe bugbounty.<br>
It's just an compressed information used to find links and infos easier!<br>
During creation of issues, we need to report CWE ID, References for Help, OWASP ID and more.<br>
> __[!!!] THIS IS NOT ABSOLUTELY TRUE/CORRECT__, if you see that something is wrong, please point it for me!
<br>
<br>
<!-- We start the references here, divided by issue types -->

<details>
  <summary>Improper Input Validation</summary>
  
    - Common Weakness Enumeration:
        CWE-20: Improper Input Validation

    - References:
        https://owasp.org/www-community/vulnerabilities/Improper_Data_Validation
        https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html

    - OWASP Web Top 10:
        A05:Security Misconfiguration

    - OWASP API Top 10:
        API7:Security Misconfiguration
        
</details>

<details>
  <summary>Insecure Direct Object Reference (IDOR)</summary>
  
    - Common Weakness Enumeration:
        CWE-639: Authorization Bypass Through User-Controlled Key

    - References:
        https://portswigger.net/web-security/access-control/idor
        https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html
        https://www.invicti.com/blog/web-security/insecure-direct-object-reference-vulnerabilities-idor/

    - OWASP Web Top 10:
        A01:Broken Access Control

    - OWASP API Top 10:
        API1:Broken Object Level Authorization
        
</details>

<details>
  <summary>Broken Access Control (BAC)</summary>
  
    - Common Weakness Enumeration:
        CWE-284: Improper Access Control

    - References:
        https://portswigger.net/web-security/access-contro
        https://owasp.org/Top10/A01_2021-Broken_Access_Control/
        https://www.eccouncil.org/cybersecurity-exchange/web-application-hacking/broken-access-control-vulnerability/

    - OWASP Web Top 10:
        A01:Broken Access Control

    - OWASP API Top 10:
        API5:Broken Function Level Authorization
        
</details>

<details>
  <summary>Rate Limiting</summary>
  
    - Common Weakness Enumeration:
        CWE-770: Allocation of Resources Without Limits or Throttling

    - References:
        https://www.cloudflare.com/learning/bots/what-is-rate-limiting/
        https://kb.intigriti.com/en/articles/5678905-understanding-rate-limiting
        https://apisecurity.io/encyclopedia/content/owasp/api4-lack-of-resources-and-rate-limiting.htm
        https://www.akana.com/blog/rate-limiting

    - OWASP Web Top 10:
        A05:Security Misconfiguration

    - OWASP API Top 10:
        API4:Lack of Resources & Rate Limiting
        
</details>

<details>
  <summary>Business Logic Errors</summary>
  
    - Common Weakness Enumeration:
        CWE-841: Improper Enforcement of Behavioral Workflow

    - References:
        https://portswigger.net/web-security/logic-flaws
        https://portswigger.net/web-security/logic-flaws/examples
        https://owasp.org/www-community/vulnerabilities/Business_logic_vulnerability

    - OWASP Web Top 10:
        A04:Insecure Design

    - OWASP API Top 10:
        API7:Security Misconfiguration
        
</details>

<details>
  <summary>HTML Injection</summary>
  
    - Common Weakness Enumeration:
        CWE-80: Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS)

    - References:
        https://www.acunetix.com/vulnerabilities/web/html-injection/
        https://www.invicti.com/learn/html-injection/
        https://www.softwaretestinghelp.com/html-injection-tutorial/

    - OWASP Web Top 10:
        A03:Injection

    - OWASP API Top 10:
        API8:Injection
        
</details>

<details>
  <summary>Reflected/DOM/Self/Stored Cross-site scripting</summary>
  
    - Common Weakness Enumeration:
        CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

    - References:
        https://owasp.org/www-community/attacks/xss/
        https://portswigger.net/web-security/cross-site-scripting
        https://www.invicti.com/learn/cross-site-scripting-xss/
        https://blog.intigriti.com/hackademy/cross-site-scripting-xss/

    - OWASP Web Top 10:
        A03:Injection

    - OWASP API Top 10:
        API8:Injection
        
</details>

<details>
  <summary>SQL Injection</summary>
  
    - Common Weakness Enumeration:
        CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')

    - References:
        https://portswigger.net/web-security/sql-injection
        https://owasp.org/www-community/attacks/SQL_Injection
        https://www.invicti.com/learn/sql-injection-sqli/

    - OWASP Web Top 10:
        A03:Injection

    - OWASP API Top 10:
        API8:Injection
        
</details>

<details>
  <summary>Improper Error Handling</summary>
  
    - Common Weakness Enumeration:
        CWE-209: Generation of Error Message Containing Sensitive Information

    - References:
        https://deviq.com/practices/descriptive-error-messages
        https://owasp.org/www-community/Improper_Error_Handling

    - OWASP Web Top 10:
        A05:Security Misconfiguration

    - OWASP API Top 10:
        API7:Security Misconfiguration
        
</details>

<details>
  <summary>Broken Link Hijacking</summary>
  
    - Common Weakness Enumeration:
        CWE-610: Externally Controlled Reference to a Resource in Another Sphere

    - References:
        https://www.acunetix.com/vulnerabilities/web/broken-link-hijacking/
        https://www.indusface.com/blog/what-is-broken-link-hijacking/
        https://www.cobalt.io/blog/hunting-for-broken-link-hijacking-blh

    - OWASP Web Top 10:
        A05:Security Misconfiguration

    - OWASP API Top 10:
        API7:Security Misconfiguration
        
</details>

<details>
  <summary>Open Redirection</summary>
  
    - Common Weakness Enumeration:
        CWE-601: URL Redirection to Untrusted Site ('Open Redirect')

    - References:
        https://blog.intigriti.com/hackademy/open-redirect/
        https://learn.snyk.io/lessons/open-redirect/javascript/
        https://portswigger.net/kb/issues/00500100_open-redirection-reflected
        https://www.invicti.com/blog/web-security/open-redirect-vulnerabilities-invicti-pauls-security-weekly/

    - OWASP Web Top 10:
        A05:Security Misconfiguration

    - OWASP API Top 10:
        API7:Security Misconfiguration
        
</details>

<details>
  <summary>User Enumeration</summary>
  
    - Common Weakness Enumeration:
        CWE-203: Observable Discrepancy

    - References:
        https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/03-Identity_Management_Testing/04-Testing_for_Account_Enumeration_and_Guessable_User_Account
        https://www.virtuesecurity.com/kb/username-enumeration/
        https://www.rapid7.com/blog/post/2017/06/15/about-user-enumeration/

    - OWASP Web Top 10:
        A04:Insecure Design

    - OWASP API Top 10:
        API7:Security Misconfiguration
        
</details>

<details>
  <summary>Clickjacking/UI Reddresing</summary>
  
    - Common Weakness Enumeration:
        CWE-1021: Improper Restriction of Rendered UI Layers or Frames

    - References:
        https://www.acunetix.com/vulnerabilities/web/clickjacking-x-frame-options-header/
        https://portswigger.net/web-security/clickjacking
        https://www.invicti.com/learn/clickjacking/

    - OWASP Web Top 10:
        A05:Security Misconfiguration

    - OWASP API Top 10:
        API7:Security Misconfiguration
        
</details>

<details>
  <summary>Cross Site Request Forgery (CSRF)</summary>
  
    - Common Weakness Enumeration:
        CWE-352: Cross-Site Request Forgery (CSRF)

    - References:
        https://blog.intigriti.com/hackademy/cross-site-request-forgery-csrf/
        https://portswigger.net/web-security/csrf
        https://www.invicti.com/web-vulnerability-scanner/vulnerabilities/cross-site-request-forgery/

    - OWASP Web Top 10:
        A05:Security Misconfiguration

    - OWASP API Top 10:
        API7:Security Misconfiguration
        
</details>

<details>
  <summary>Server Side Request Forgery (SSRF)</summary>
  
    - Common Weakness Enumeration:
        CWE-918: Server-Side Request Forgery (SSRF)

    - References:
    https://blog.intigriti.com/hackademy/server-side-request-forgery-ssrf/
    https://portswigger.net/web-security/ssrf
    https://www.invicti.com/learn/server-side-request-forgery-ssrf/
    https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/

    - OWASP Web Top 10:
        A10:Server-Side Request Forgery

    - OWASP API Top 10:
        API7:Security Misconfiguration
        
</details>

<details>
  <summary>Improper Authorization</summary>
  
    - Common Weakness Enumeration:
        CWE-285: Improper Authorization

    - References:
        https://owasp.org/Top10/TC/A3
        https://www.sans.org/security-awareness-training/cyber-security-topics/improper-authorization-access-control
        https://www.webappsec.org/projects/threat/classes/access_control_flaws.shtml

    - OWASP Web Top 10:
        A07:Identification and Authentication Failures

    - OWASP API Top 10:
        API1:Broken Object Level Authorization
        
</details>

<details>
  <summary>Privilege Escalation (Horizontal/Vertical)</summary>
  
    - Common Weakness Enumeration:
        CWE-269: Improper Privilege Management

    - References:
        https://www.sans.org/security-awareness-training/vertical-horizontal-privilege-escalation
        https://portswigger.net/web-security/access-control

    - OWASP Web Top 10:
        A01:Broken Access Control

    - OWASP API Top 10:
        API5:Broken Function Level Authorization
        
</details>

<details>
  <summary>Brute Forcing</summary>
  
    - Common Weakness Enumeration:
        CWE-307: Improper Restriction of Excessive Authentication Attempts

    - References:
        https://www.kaspersky.com/resource-center/definitions/brute-force-attack
        https://owasp.org/www-community/controls/Blocking_Brute_Force_Attacks
        https://sucuri.net/guides/what-is-brute-force-attack/

    - OWASP Web Top 10:
        A05:Security Misconfiguration

    - OWASP API Top 10:
        API7:Security Misconfiguration
        
</details>

<details>
  <summary>Unprotected Credentials</summary>
  
    - Common Weakness Enumeration:
        CWE-522: Insufficiently Protected Credentials

    - Desscription:
        This case refers to situations where the credentials, keys or tokens are not well protected and encrypted.
        It could lead to possible theft or compromise.
        An example is a attacker get credentials by phishing, social engineering, or exploiting vulnerabilities, and use it to access company systems.
        This usage of valid credentials, could lead to malicious actions, such as stealing data, altering data, or executing unauthorized commands.

    - References:
        N/A

    - OWASP Web Top 10:
        A05:Security Misconfiguration

    - OWASP API Top 10:
        API7:Security Misconfiguration
        
</details>

<details>
  <summary>Missing Authentication</summary>
  
    - Common Weakness Enumeration:
        CWE-306: Missing Authentication for Critical Function

    - Desscription:
        The application does not have any authentication for access some functions.
        It does not require any kind of access, leading to full anonymous access.   

    - References:
        https://auth0.com/docs/get-started/applications/confidential-and-public-applications

    - OWASP Web Top 10:
        A05:Security Misconfiguration

    - OWASP API Top 10:
        API7:Security Misconfiguration
        
</details>

<details>
  <summary>Exposure of Sensitive Information</summary>
  
    - Common Weakness Enumeration:
        CWE-200: Exposure of Sensitive Information to an Unauthorized Actor

    - Desscription:
        The application does not handle sensitive information correctly, this could lead to exposure of credentials, tokens, and more.
        This is an initial step for any attacker, called information gathering.

    - References:
        https://portswigger.net/web-security/information-disclosure
        https://knowledge-base.secureflag.com/vulnerabilities/sensitive_information_exposure/sensitive_information_disclosure_vulnerability.html
        https://www.invicti.com/blog/web-security/information-disclosure-issues-attacks/

    - OWASP Web Top 10:
        A05:Security Misconfiguration

    - OWASP API Top 10:
        API7:Security Misconfiguration
        
</details>

