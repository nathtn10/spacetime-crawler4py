import requests
from scraper import extract_next_links

# 1. Define a Mock Response class to mimic the Crawler's input
class MockResponse:
    def __init__(self, url, status, headers, content):
        self.url = url
        self.status = status
        self.error = None
        self.raw_response = self.RawResponse(url, headers, content)

    class RawResponse:
        def __init__(self, url, headers, content):
            self.url = url
            self.headers = headers
            self.content = content

# 2. Setup the target URL
target_url = "http://cdb.ics.uci.edu/supplement/randomSmiles100K"

print(f"Testing URL: {target_url}")
print("-" * 40)

# 3. Fetch ONLY the headers (HEAD request) to be fast and safe
#    We don't download the massive body, just check what the server says.
try:
    real_resp = requests.head(target_url, timeout=5)
    server_headers = real_resp.headers
    print(f"Server Content-Type: {server_headers.get('Content-Type')}")
except Exception as e:
    print(f"Could not fetch headers: {e}")
    # Fallback to what we suspect it is for the test
    server_headers = {'Content-Type': 'text/plain'}

# 4. Create a 'Fake' body 
#    We use a small snippet of the chemical data to simulate the page content
#    without downloading the full 100MB file.
fake_content = b"CCSc1nnc(s1)NC(=O)C0c2cc(ccc2C(C)C" 

# 5. Build the Mock Object
mock_resp = MockResponse(
    url=target_url,
    status=200,
    headers=server_headers,
    content=fake_content
)

# 6. Run YOUR function
print("-" * 40)
print("Running extract_next_links()...")
links = extract_next_links(target_url, mock_resp)

# 7. Check the result
print("-" * 40)
if len(links) == 0:
    print("✅ SUCCESS: The page was correctly filtered out (returned 0 links).")
else:
    print(f"❌ FAILURE: The page was NOT filtered. It found {len(links)} links.")