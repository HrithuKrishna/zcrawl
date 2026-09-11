# Zcrawle

Thankyou for using Zcrawl!

----USAGE----

1. Make it executable

    chmod +x zcrawl.py
    chmod +x requirements.sh
    bash requirements.sh

2. Run the crawler against your target website

    python3 zcrawl.py <url>

3. Adjust parameters

    To crawl more pages: python3 zcrawl.py <url> --max-pages 100
    To reduce load on the server (slow down): python3 zcrawl.py <url> --delay 2.0
