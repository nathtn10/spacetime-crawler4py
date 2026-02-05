import re
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
import nltk
#nltk.download('stopwords')
from nltk.corpus import stopwords

#A set to store unique visited urls
visited_urls = set()
#Dictionary to store the longest page and its word count
longest_page= {"url": "", "words_count" : 0}
#Dictionary to store words and its counts
word_frequencies = {}
#Dictionary to store subdomains and number of pages in that subdomain {subdomain: unique pages count}
subdomains = {} 

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
    for sub, count in sorted(subdomains.items()):
        print(f"{sub}, {count}")

    print("=" * 40)

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
    links = [] 

    if resp is None or resp.status != 200 or resp.raw_response is None or not resp.raw_response.content: 
        print(resp.error)
        return links

    #Add to visited url
    visited_urls.add(url)

    #Subdomains count
    '''parsed_url = urlparse(url)
    if "uci.edu" in parsed_url.netloc:
        sub = parsed_url.netloc
        subdomains[sub] = subdomains.get(sub, 0) + 1'''
    

    soup = BeautifulSoup(resp.raw_response.content, 'lxml')
    #This gets all the text
    all_text = soup.get_text()

    tokens = tokenize(all_text)

    if len(tokens) > longest_page["words_count"] :
        longest_page["url"] = url 
        longest_page["words_count"] = len(tokens)
        

    #This gets the url from the href tags
    for link in soup.find_all('a', href=True):
        href = link['href']
        abs_url = urljoin(url, href)
        parsed_href = urlparse(abs_url)
        #Defrag
        clean_url = parsed_href.scheme + "://" + parsed_href.netloc + parsed_href.path
        if parsed_href.query:
            clean_url += "?" + parsed_href.query
        #print("appending " + clean_url)
        links.append(clean_url)
        
    
    return links


def tokenize(resp): 

    tokens = [] 
    current = []

    stop_words = stopwords.words('english')

    for ch in resp :
        if ch.isalnum() and ch.isascii() :
            current.append(ch.lower())
        else :
            if current :
                word = "".join(current)
                if word not in stop_words :
                    tokens.append(word)
                current = []

    if current :
        word = "".join(current)
        if word not in stop_words :
            tokens.append(word)

    return tokens

def top50(word_freuqncies): 
    sorted_words = sorted(word_frequencies.items(), key=lambda x: x[1])
    return sorted_words[:50]

def subdomains(visted_urls):
    subdomains = {}
    for url in visted_urls:
        parsed = urlparse(url)
        domains = parsed.netloc

        if domains.endswith("uci.edu"):
            subdomains[domains] = subdomains.get(domains, 0) + 1
    
    return sorted(subdomains.items())

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
        if not any(parsed.netloc.endswith(domain) for domain in allowed_domains):
            return False

        path_check = ["/pix/", "events", "event", ".php"]

        if any(word in parsed.path.lower() for word in path_check):
            return False

        calendar_words = ["calendar", "ical", "=date", "share="]

        if re.match(r"^.*?(/.+?/).*?\1.*?\1.*?$", parsed.path.lower()):
            return False

        if any(word in parsed.query.lower() for word in calendar_words):
            return False

        # if ".php" in parsed.path.lower():
        #     return False


        return not re.match(
            r".*\.(css|js|bmp|gif|jpe?g|ico"
            + r"|png|tiff?|mid|mp2|mp3|mp4|mpg"
            + r"|wav|avi|mov|mpeg|ram|m4v|mkv|ogg|ogv|pdf"
            + r"|ps|eps|tex|ppt|pptx|doc|docx|xls|xlsx|names"
            + r"|data|dat|exe|bz2|tar|msi|bin|7z|psd|dmg|iso"
            + r"|epub|dll|cnf|tgz|sha1"
            + r"|thmx|mso|arff|rtf|jar|csv"
            + r"|rm|smil|wmv|swf|wma|zip|rar|gz)$", parsed.path.lower())

    except (TypeError, ValueError):
        print("Skipping malformed URL: " + url)
        raise
