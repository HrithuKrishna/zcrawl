import os
import sys
import time
import argparse
import logging
from urllib.parse import urljoin, urlparse, urlunparse
import requests
from bs4 import BeautifulSoup
import urllib3

# Suppress InsecureRequestWarning for HTTPS checks if needed
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configure Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class WebVulnCrawler:
    def __init__(self, target_url, max_pages=50, delay=1.0):
        self.target_url = target_url.rstrip('/')
        self.max_pages = max_pages
        self.delay = delay
        self.visited_urls = set()
        self.queue = [self.target_url]

        # Headers to simulate a browser
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
        }

        # Stores findings
        self.vulnerabilities = {
            'xss_potential': [],
            'sqli_potential': [],
            'open_redirect': [],
            'ssl_issues': []
        }

    def get_domain(self, url):
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}"

    def is_same_domain(self, url):
        return self.get_domain(url) == self.get_domain(self.target_url)

    def add_vulnerability(self, vuln_type, details):
        if details not in [v[0] for v in self.vulnerabilities[vuln_type]]:
            self.vulnerabilities[vuln_type].append((details, time.strftime("%H:%M:%S")))
            logger.info(f"Found {vuln_type}: {details}")

    def check_xss_potential(self, html_content):
        """Simple heuristic for XSS: Look for inputs without quotes or unescaped text."""
        soup = BeautifulSoup(html_content, 'html.parser')

        # Check input fields for lack of escaping (naive)
        inputs = soup.find_all('input')
        for inp in inputs:
            value = inp.get('value', '')
            if '<' in value or '>' in value or '"' in value:
                self.add_vulnerability('xss_potential', f"Unescaped input: <{inp.get('name', 'unknown')}='{value}'>")

        # Check for script tags with dynamic content (naive)
        scripts = soup.find_all('script')
        for script in scripts:
            if script.string and ('document.write' in script.string or '{{' in script.string):
                self.add_vulnerability('xss_potential', f"Dynamic script content found")

    def check_sqli_potential(self, url):
        """Check URL parameters for common SQLi patterns."""
        parsed = urlparse(url)
        query_params = parsed.query.split('&')

        for param in query_params:
            if '=' in param:
                key, val = param.split('=', 1)
                # Check if value contains special characters that might indicate unescaped input
                if any(char in val for char in ["'", '"', ' ', '%', '-']):
                    # Simulate a GET request to see if it returns 200 OK (no crash)
                    try:
                        response = requests.get(urljoin(self.target_url, url), headers=self.headers, verify=True)
                        if response.status_code == 200:
                            self.add_vulnerability('sqli_potential', f"Parameter '{key}={val}' might be vulnerable")
                    except Exception as e:
                        logger.debug(f"Error checking {key}: {e}")

    def check_open_redirect(self, html_content):
        """Look for links with href pointing to external domains."""
        soup = BeautifulSoup(html_content, 'html.parser')
        current_domain = self.get_domain(self.target_url)

        anchors = soup.find_all('a', href=True)
        for a in anchors:
            href = a['href']
            if href.startswith('http') and not href.startswith(current_domain):
                self.add_vulnerability('open_redirect', f"External link: {href}")

    def check_ssl(self, url):
        """Check SSL certificate validity."""
        parsed = urlparse(url)
        if parsed.scheme == 'https':
            try:
                response = requests.get(url, headers=self.headers, verify=True, timeout=5)
                # If we get here without error, SSL is likely valid.
                # We can also check the certificate details if needed.
            except requests.exceptions.SSLError as e:
                self.add_vulnerability('ssl_issues', f"SSL Error in {url}: {str(e)}")

    def crawl(self):
        logger.info(f"Starting crawl for {self.target_url} (Max Pages: {self.max_pages})")

        while self.queue and len(self.visited_urls) < self.max_pages:
            current_url = self.queue.pop(0)

            if current_url in self.visited_urls:
                continue

            logger.debug(f"Crawling: {current_url}")

            try:
                # Fetch the page
                response = requests.get(current_url, headers=self.headers, verify=True, timeout=5)

                if response.status_code != 200:
                    logger.debug(f"Skipping {current_url} (Status: {response.status_code})")
                    continue

                html_content = response.text

                # Check for vulnerabilities
                self.check_xss_potential(html_content)
                self.check_sqli_potential(current_url)
                self.check_open_redirect(html_content)
                self.check_ssl(current_url)

                # Add to visited
                self.visited_urls.add(current_url)

                # Find and queue new links (same domain, HTML pages)
                soup = BeautifulSoup(html_content, 'html.parser')
                anchors = soup.find_all('a', href=True)

                for a in anchors:
                    href = a['href']
                    # Skip anchors that are not links (e.g., #section)
                    if not href.startswith('#') and not href.startswith('javascript:'):
                        absolute_url = urljoin(current_url, href)

                        # Filter out non-HTML pages and external domains (based on config)
                        parsed_href = urlparse(absolute_url)
                        ext_domain = self.get_domain(absolute_url)
                        current_ext_domain = self.get_domain(self.target_url)

                        if ext_domain == current_ext_domain:
                            # Check if already visited or in queue
                            if absolute_url not in self.visited_urls and absolute_url not in self.queue:
                                # Add only HTML pages (simple extension check)
                                if parsed_href.path.endswith(('.html', '.htm', '/')) or not parsed_href.path.split('.')[-1] in ['jpg', 'png', 'css', 'js', 'pdf']:
                                    self.queue.append(absolute_url)

                time.sleep(self.delay)

            except Exception as e:
                logger.error(f"Error crawling {current_url}: {str(e)}")

    def print_report(self):
        """Print a formatted report of found vulnerabilities."""
        print("\n" + "="*50)
        print("VULNERABILITY REPORT FOR:", self.target_url)
        print("="*50)

        for vuln_type, details_list in self.vulnerabilities.items():
            if details_list:
                print(f"\n[ {vuln_type.upper()} ]")
                for detail, timestamp in details_list:
                    print(f"  - [{timestamp}] {detail}")
            else:
                print(f"\n[ {vuln_type.upper()} ] No issues found.")

        print("\n" + "="*50)
        print("Crawled URLs:", len(self.visited_urls))
        print("="*50)

def main():
    parser = argparse.ArgumentParser(description='Web Vulnerability Crawler for Linux')
    parser.add_argument('url', help='Target URL to crawl (e.g., https://example.com)')
    parser.add_argument('-m', '--max-pages', type=int, default=50, help='Maximum number of pages to crawl (default: 50)')
    parser.add_argument('-d', '--delay', type=float, default=1.0, help='Delay between requests in seconds (default: 1.0)')

    args = parser.parse_args()

    if not args.url.startswith('http'):
        args.url = 'https://' + args.url

    crawler = WebVulnCrawler(args.url, max_pages=args.max_pages, delay=args.delay)
    crawler.crawl()
    crawler.print_report()

if __name__ == '__main__':
    main()
