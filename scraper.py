import re
from urllib.parse import urlparse
from bs4 import BeautifulShop
import nltk
nltk.download('stopwords')
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
    return [link for link in links if is_valid(link)]

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

    if resp is None or resp.status != 200 or resp.raw_response is None or resp.raw_response.content: 
        print(resp.error)
        return links

    #Add to visited url
    visited_urls.add(url)

    #Subdomains count
    parsed_url = urlparse(url)
    if "uci.edu" in parsed_url.netloc:
        sub = parsed_url.netloc
        subdomains[sub] = subdomains.get(sub, 0) + 1

    soup = BeautifulSoup(resp.raw_response.content, 'html.parser')
    #This gets all the text
    all_text = soup.get_text()

    #This gets the url from the href tags
    for link in soup.find_all('a', href=True)
        href = link['href']

        #parsed_href = urlparse(href)
        #Defragment
        #parsed_href._replace(fragment="").geturl()
        
    
    return list()


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

        return not re.match(
            r".*\.(css|js|bmp|gif|jpe?g|ico"
            + r"|png|tiff?|mid|mp2|mp3|mp4"
            + r"|wav|avi|mov|mpeg|ram|m4v|mkv|ogg|ogv|pdf"
            + r"|ps|eps|tex|ppt|pptx|doc|docx|xls|xlsx|names"
            + r"|data|dat|exe|bz2|tar|msi|bin|7z|psd|dmg|iso"
            + r"|epub|dll|cnf|tgz|sha1"
            + r"|thmx|mso|arff|rtf|jar|csv"
            + r"|rm|smil|wmv|swf|wma|zip|rar|gz)$", parsed.path.lower())

    except TypeError:
        print ("TypeError for ", parsed)
        raise
