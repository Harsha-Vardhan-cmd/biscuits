import requests
import base64
import json
import jwt
import re
from termcolor import colored
from prettytable import PrettyTable

def print_banner():
    banner = """
██████╗ ██╗███████╗ ██████╗██╗   ██╗██╗████████╗███████╗
██╔══██╗██║██╔════╝██╔════╝██║   ██║██║╚══██╔══╝██╔════╝
██████╔╝██║███████╗██║     ██║   ██║██║   ██║   ███████╗
██╔══██╗██║╚════██║██║     ██║   ██║██║   ██║   ╚════██║
██████╔╝██║███████║╚██████╗╚██████╔╝██║   ██║   ███████║
╚═════╝ ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝   ╚═╝   ╚══════╝
                                                                                              
    Welcome to Biscuits - Let's break down cookies, no cap.
                    by rsha
    """
    print(colored(banner, "cyan"))

print_banner()

# Improved Base64 check with better validation
def is_base64(s):
    s = s.strip()
    # Skip common session IDs which often trigger false positives
    if len(s) <= 5:  # Too short to be meaningful base64
        return False
        
    # More strict pattern for base64
    pattern = r'^[A-Za-z0-9+/]+={0,2}$'
    if not re.match(pattern, s):
        return False
    
    try:
        decoded = base64.b64decode(s, validate=True)
        # Check if the decoded result makes sense
        try:
            # Check if it's readable text
            text = decoded.decode('utf-8')
            # If it has a reasonable amount of printable characters, it's likely base64 text
            printable_ratio = sum(c.isprintable() for c in text) / len(text)
            return printable_ratio > 0.8
        except UnicodeDecodeError:
            # If it's not readable text, it might be binary data
            # Return False for likely session IDs or other binary data
            return False
    except Exception:
        return False

# Improved decoder with better binary data handling
def decode_base64(encoded_data):
    try:
        encoded_data = encoded_data.strip()
        encoded_data = re.sub(r'[^A-Za-z0-9+/=]', '', encoded_data)
        if len(encoded_data) % 4 != 0:
            encoded_data += "=" * (4 - len(encoded_data) % 4)  # Add padding if needed
        decoded_bytes = base64.b64decode(encoded_data)
        try:
            # Try decoding to utf-8 if possible
            return decoded_bytes.decode("utf-8")
        except UnicodeDecodeError:
            # If it's not valid UTF-8 text, return a hex representation
            return f"Binary data (hex): {decoded_bytes.hex()[:50]}..."
    except Exception as e:
        return f"(error decoding base64: {e})"

# JWT detection
def decode_jwt(token):
    try:
        header = jwt.get_unverified_header(token)
        payload = jwt.decode(token, options={"verify_signature": False})
        return header, payload
    except Exception:
        return None, None

def color_boolean(val):
    return colored("YES", "green") if val else colored("NO", "red")

def fetch_cookies(url):
    response = requests.get(url)
    cookies = response.cookies
    cookie_list = []

    global missing_csp
    missing_csp = "Content-Security-Policy" not in response.headers

    set_cookie_header = response.headers.get('Set-Cookie', '')

    for cookie in cookies:
        cookie_data = {
            "name": cookie.name,
            "value": cookie.value,
            "secure": "Secure" in set_cookie_header,
            "httponly": "HttpOnly" in set_cookie_header,
            "samesite": "SameSite" in set_cookie_header,
            "domain": cookie.domain,
            "path": cookie.path,
            "max-age": None,
            "expires": None
        }

        cookie_str = f"{cookie.name}={cookie.value}"
        if "max-age" in cookie_str:
            cookie_data["max-age"] = "Max-Age"
        if "expires" in cookie_str:
            cookie_data["expires"] = "Expires"

        cookie_list.append(cookie_data)

    return cookie_list

def analyze_cookies(cookies):
    table = PrettyTable()
    table.field_names = ["Cookie Name", "Secure", "HttpOnly", "SameSite", "Domain Scope", "Max-Age/Expires", "Findings"]

    for cookie in cookies:
        secure = color_boolean(cookie.get("secure", False))
        httponly = color_boolean(cookie.get("httponly", False))
        samesite = cookie.get("samesite", "None")
        domain = cookie.get("domain", "")
        path = cookie.get("path", "/")
        max_age = cookie.get('max-age', 'None')
        expires = cookie.get('expires', 'None')

        domain_scope = "Subdomain Accessible" if domain.startswith(".") else colored("Tightly Scoped", "yellow")

        findings = []
        value = cookie["value"]
        
        # Skip base64 detection for common session cookies
        is_session_cookie = cookie["name"].lower() in ["phpsessid", "sessionid", "jsessionid", "aspsessionid"]

        # Base64 detection with session cookie check
        if not is_session_cookie and is_base64(value):
            findings.append("Base64 Encoded")
            decoded = decode_base64(value)
            findings.append(f"Decoded: {decoded}")

        # JWT detection
        header, payload = decode_jwt(value)
        if header and payload:
            findings.append("JWT Token Detected")
            findings.append("JWT Header: " + json.dumps(header, indent=2))
            findings.append("JWT Payload: " + json.dumps(payload, indent=2))

        # Domain & Path
        if not domain.startswith("."):
            findings.append("Tightly scoped domain – may lead to session fixation")
        if path != "/":
            findings.append("Cookie not set to root path – risk of fixation")

        # Max-Age
        if not max_age:
            findings.append("No Max-Age set – cookie may expire at the session end")

        # SameSite
        if isinstance(samesite, str) and samesite.lower() == "none":
            findings.append("SameSite is None – vulnerable to CSRF attacks")

        # XSS-related
        if not cookie.get("secure"):
            findings.append("Missing Secure flag – vulnerable to XSS attacks")

        if not cookie.get("httponly"):
            findings.append("Missing HttpOnly flag – vulnerable to XSS attacks")

        if missing_csp:
            findings.append("Missing CSP header – entire site may be vulnerable to XSS")

        table.add_row([
            cookie["name"],
            secure,
            httponly,
            samesite,
            domain_scope,
            f"{max_age} / {expires}",
            "\n".join(findings) if findings else "None"
        ])

    print(table)

def main():
    url = input("Enter URL to analyze: ")
    cookies = fetch_cookies(url)
    analyze_cookies(cookies)

if __name__ == "__main__":
    main()
