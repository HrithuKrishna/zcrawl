# Zcrawle

A lightweight, single-file Python tool designed for Linux to crawl websites and detect common web application vulnerabilities such as XSS, SQL Injection (SQLi), Open Redirects, and SSL issues.

This tool is optimized for performance and ease of use, making it ideal for security professionals and developers who need to quickly assess the security posture of their web applications directly from the command line.
📋 Features

    XSS Detection: Identifies potential Cross-Site Scripting vulnerabilities by analyzing input fields and dynamic script content.
    SQLi Potential: Checks URL parameters for common SQL injection patterns.
    Open Redirects: Finds external links that may be susceptible to open redirect attacks.
    SSL Validation: Verifies SSL certificate validity during the crawl.
    Domain Isolation: Automatically filters and crawls only links within the same domain (configurable).
    Rate Limiting: Adjustable delay between requests to prevent overwhelming the target server.
    Detailed Reporting: Outputs a structured report with timestamps for all findings.

🚀 Getting Started
Prerequisites

    Linux OS (Ubuntu, Debian, CentOS, etc.)
    Python 3 installed.
