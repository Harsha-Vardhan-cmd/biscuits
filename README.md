# 🧁 Biscuits - Cookie Analyzer

![image](https://github.com/user-attachments/assets/be5e2d92-0bfd-406c-b179-6706ea22ebb5)


Biscuits is a lightweight Python tool to help bug bounty hunters, developers, and infosec enthusiasts analyze cookies for common security misconfigurations — including **JWT tokens**, **Base64 values**, and missing flags like `Secure`, `HttpOnly`, and `SameSite`.

Most people ignore cookies or let them pass unnoticed — but **Biscuits** helps you break them down, no cap.

---

## 🚀 Features

- 🔍 **Auto-detects JWT tokens** in cookies and decodes the header & payload
- 📦 **Detects Base64-encoded values** and decodes them for easy reading
- 🛡️ Flags cookies missing:
  - `Secure`
  - `HttpOnly`
  - `SameSite`
  - `Max-Age` or `Expires`
- 🌍 Highlights cookie scoping (subdomain/tight)
- ❌ Warns if CSP header is missing (which can lead to XSS)
- ⚡ Fast, CLI-based, no bloat — just vibes and results

---

## 🔧 How to Use

1. Install dependencies
   pip install -r requirements.txt
2. Run the tool
   python biscuits.py


Enter any URL, and Biscuits will fetch the cookies and break them down for you.
