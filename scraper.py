from curses.ascii import isalpha
import re
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
import nltk
nltk.download('stopwords')
from nltk.corpus import stopwords
from nltk.tokenize import word_tokenize
from nltk.tokenize import RegexpTokenizer

#A set to store unique visited urls
visited_urls = set()
#Dictionary to store the longest page and its word count
longest_page= {"url": "", "words_count" : 0}
#Dictionary to store words and its counts
word_frequencies = {}
#Dictionary to store subdomains and number of pages in that subdomain {subdomain: unique pages count}
subdomains = {} 
#Load the english words in nltk
low_quality_pages = set()
visited_exact_hashes = set()
visited_simhashes = {}
duplicate_count = 0

def scraper(url, resp):
    links = extract_next_links(url, resp)
    if len(visited_urls) % 50 == 0:
        print_final_report()

        # Optional: Save to a file instead of just printing
        with open("crawler_report.txt", "w") as f:
            f.write(f"Unique Pages: {len(visited_urls)}\n")
            f.write(f"Longest Page: {longest_page['url']} ({longest_page['words_count']})\n")

    return [link for link in links if is_valid(link)]


def print_final_report():
    print("=" * 40)
    print(f"FINAL REPORT")
    print("=" * 40)

    # 1. Unique Pages
    print(f"Unique Pages Found: {len(visited_urls)}")

    # 2. Longest Page
    print(f"Longest Page: {longest_page['url']}")
    print(f"Word Count: {longest_page['words_count']}")

    # 3. Top 50 Common Words
    print("-" * 40)
    print("Top 50 Common Words")
    print("-" * 40)
    # Sort by count (descending) and take top 50
    sorted_words = sorted(word_frequencies.items(), key=lambda x: x[1], reverse=True)[:50]
    for word, count in sorted_words:
        print(f"{word}: {count}")

    # 4. Subdomains
    print("-" * 40)
    print("Subdomains in ics.uci.edu")
    print("-" * 40)
    # Sort alphabetically
    for sub, count in sorted(count_subdomains(visited_urls)): #subdomains.items()):
        print(f"{sub}, {count}")

    print("=" * 40)
    print(f"Get rid of near dup page, {duplicate_count}")


def extract_next_links(url, resp):
    # Implementation required.
    # url: the URL that was used to get the page
    # resp.url: the actual url of the page
    # resp.status: the status code returned by the server. 200 is OK, you got the page. Other numbers mean that there was some kind of problem.
    # resp.error: when status is not 200, you can check the error here, if needed.
    # resp.raw_response: this is where the page actually is. More specifically, the raw_response has two parts:
    #         resp.raw_response.url: the url, again
    #         resp.raw_response.content: the content of the page!
    # Return a list with the hyperlinks (as strings) scrapped from resp.raw_response.content
    global duplicate_count
    links = [] 

    #change
    if resp is None or resp.status != 200 : 
        print(resp.error)
        return links
    if resp.raw_response is None or not resp.raw_response.content: 
        print(resp.error)
        return links 

    #Check if its text
    content_type = resp.raw_response.headers.get('Content-Type', '').lower()
    if "text" not in content_type and "html" not in content_type:
        return links

    #Add to visited url
    visited_urls.add(url)

    #Filtering out pages that are possibly not html or is word dump
    if not re.search(rb'<[a-z][^>]*>', resp.raw_response.content, re.IGNORECASE):
        print(f"Skipping non-HTML (No tags found): {url}")
        with open("filtered_pages.log", "a") as log_file:
            log_file.write(f"Filtered (Low Quality): {url}\n")
        return links  # (which is empty [])
    '''
    if(is_low_quality(soup)):
        print(f"low quality data dump page {url}")
        low_quality_pages.add(url)
        with open("filtered_pages.log", "a") as log_file:
            log_file.write(f"Filtered (Low Quality): {url}\n")
        return []
    '''
    soup = BeautifulSoup(resp.raw_response.content, 'lxml')

    for script in soup(["script", "style"]):
        script.extract()

    # 1. Get the text
    all_text = soup.get_text()
    
    # 2. CHECK EXACT DUPLICATES (Fastest check first)
    # We use the standard python hash for this
    exact_hash = hash(all_text)
    if exact_hash in visited_exact_hashes:
        return []  # Skip exact duplicate
    visited_exact_hashes.add(exact_hash)

    # 3. CHECK NEAR DUPLICATES (Slower, requires SimHash)
    tokens = tokenize(all_text)
    
    # Check if page has enough content to be worth checking
    if len(tokens) < 5:
        return []

    fingerprint = simhash(tokens)
    
    # Compare this fingerprint against all PREVIOUS SimHash fingerprints
    is_near_duplicate = False
    for seen_fp, origin_url in visited_simhashes.items():
        # Calculate distance between two SimHash fingerprints
        dist = get_hamming_distance(fingerprint, seen_fp)
        
        # Threshold: 0 means identical, 1 means very close
        if dist <= 1:
            print(f"Skipping near-duplicate: {url}")
            print(f"   -> Similar to: {origin_url}")        
            with open("filtered_pages.log", "a") as log_file:
                log_file.write(f"Skipping near-duplicate: {url}    -> Similar to: {origin_url}\n")
            duplicate_count += 1
            is_near_duplicate = True
            break
            
    if is_near_duplicate:
        return [] # Skip this page

    # If it's unique, add the fingerprint to the SimHash set
    visited_simhashes[fingerprint] = url
    '''
    #This gets all the text
    all_text = soup.get_text()
    content_hash = hash(all_text)

    if content_hash in visited_content_hashes:
        return [] # Skip duplicate

    visited_content_hashes.add(content_hash)


    tokens = tokenize(all_text)
    # If page has almost no or low content, skip SimHash
    if len(tokens) < 5:
        return []

    fingerprint = simhash(tokens)
    is_near_duplicate = False
    for seen_fp in visited_content_hashes:
        # If pages differ by 1 bit or less (very similar)
        if get_hamming_distance(fingerprint, seen_fp) <= 1:
            print(f"Skipping near-duplicate: {url}")
            duplicate_count += 1
            is_near_duplicate = True
            break
            
    if is_near_duplicate:
        return [] # Skip this page

    # If unique, add to our list and proceed
    visited_content_hashes.add(fingerprint)
    '''


    for word in tokens:
        word_frequencies[word] = word_frequencies.get(word, 0) + 1


    if len(tokens) > longest_page["words_count"] :
        longest_page["url"] = url 
        longest_page["words_count"] = len(tokens)
        

    #This gets the url from the href tags
    for link in soup.find_all('a', href=True):
        href = link['href']
        try:
            abs_url = urljoin(url, href)
            parsed_href = urlparse(abs_url)

            #Skip non http schemes like mailto: or javascript:
            if parsed_href.scheme not in ["http", "https"]:
                continue

            #Defrag
            #clean_url = parsed_href.scheme + "://" + parsed_href.netloc + parsed_href.path
            #if parsed_href.query:
                #clean_url += "?" + parsed_href.query
            clean_url = parsed_href._replace(fragment="").geturl()

            #print("appending " + clean_url)
            links.append(clean_url)
        except ValueError:
            print("Skipping parsed error URL: " + url)
            continue
        
    
    return links

TOKENIZER = RegexpTokenizer(r"[a-zA-Z0-9]{2,}")
stop_words = stopwords.words('english')
def tokenize(resp): 
    tokens = [] 


    for tok in TOKENIZER.tokenize(resp):
        tok = tok.lower()

        if tok in stop_words:
            continue

        #Skip if a token is a letter repeat
        if re.search(r"(.)\1\1\1", tok):
            continue

        tokens.append(tok)


    return tokens

#Detect if the web page is data dump
def is_low_quality(soup):
    if soup.find('pre') and len(soup.find_all('p')) < 1:
        return True

def top50(word_freuqncies): 
    sorted_words = sorted(word_frequencies.items(), key=lambda x: x[1])
    return sorted_words[:50]

def count_subdomains(visted_urls):
    subdomains = {}
    for url in visted_urls:
        parsed = urlparse(url)
        domains = parsed.netloc

        if domains.endswith("uci.edu"):
            subdomains[domains] = subdomains.get(domains, 0) + 1
    
    return sorted(subdomains.items())

def simhash(tokens):
    # Initialize 64-bit vector with zeros
    v = [0] * 64
    
    for token in tokens:
        # 1. Hash the token 
        # We use Python's built-in hash(). 
        # Note: In a real search engine, you'd use a stable hash like MD5,
        # but hash() is fine for a single-run crawler assignment.
        token_hash = hash(token)
        
        # 2. Vector Addition
        for i in range(64):
            # Check the i-th bit of the hash
            bit = (token_hash >> i) & 1
            
            # If bit is 1, add weight (1). If 0, subtract weight (-1).
            if bit == 1:
                v[i] += 1
            else:
                v[i] -= 1
                
    # 3. Create Fingerprint
    fingerprint = 0
    for i in range(64):
        if v[i] > 0:
            # Set the i-th bit to 1
            fingerprint |= (1 << i)
            
    return fingerprint

def get_hamming_distance(f1, f2):
    # XOR compares the bits (1 means they are different)
    x = (f1 ^ f2) & ((1 << 64) - 1)
    
    # Count the number of 1s (differences)
    distance = 0
    while x:
        distance += 1
        x &= x - 1
    return distance

def is_valid(url):
    # Decide whether to crawl this url or not. 
    # If you decide to crawl it, return True; otherwise return False.
    # There are already some conditions that return False.
    try:
        parsed = urlparse(url)
        if parsed.scheme not in set(["http", "https"]):
            return False

        #Specification 3 - 1
        #Check if domain ends with the allowed domains
        allowed_domains = ["ics.uci.edu", "cs.uci.edu", "informatics.uci.edu", "stat.uci.edu"]
        
        # Check 1: Is it an exact match? (e.g., "cs.uci.edu")
        # Check 2: Is it a subdomain? (e.g., "vision.cs.uci.edu")
        # We add a "." before the domain to ensure we don't match "physics.uci.edu"
        is_allowed = False
        for domain in allowed_domains:
            if parsed.netloc == domain or parsed.netloc.endswith("." + domain):
                is_allowed = True
                break
        
        if not is_allowed:
            return False

        path_check = ["/pix/", "events", ".php", "zip-attachment", "dataset"]

        if any(word in parsed.path.lower() for word in path_check):
            return False

        query_check = ["calendar", "ical", "=date", "share=", "version=", "action=history", "format=txt", "precision=second"]

        if re.match(r"^.*?(/.+?/).*?\1.*?\1.*?$", parsed.path.lower()):
            return False

        if any(word in parsed.query.lower() for word in query_check):
            return False

        # Block Apache Directory Sorting parameters
        if re.search(r"c=[a-z];o=[a-z]", parsed.query.lower()):
            return False

        # if ".php" in parsed.path.lower():
        #     return False


        return not re.match(
            r".*\.(css|js|bmp|gif|jpe?g|ico"
            + r"|png|tiff?|mid|mp2|mp3|mp4|mpg"
            + r"|wav|avi|mov|mpeg|ram|m4v|mkv|ogg|ogv|pdf"
            + r"|ps|eps|tex|ppt|pptx|doc|docx|xls|xlsx|names|ppsx|mol|bib|git|war|img"
            + r"|data|dat|exe|bz2|tar|msi|bin|7z|psd|dmg|iso"
            + r"|epub|dll|cnf|tgz|sha1"
            + r"|thmx|mso|arff|rtf|jar|csv"
            + r"|rm|smil|wmv|swf|wma|zip|rar|gz)$", parsed.path.lower())

    except (TypeError, ValueError):
        print("Malformed URL: " + url)
        return False
