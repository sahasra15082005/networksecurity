# networksecurity/utils/feature/feature_extractor.py
import re
import socket
import requests
import whois
import datetime
import tldextract
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup

# Constants
REQUEST_TIMEOUT = 5
SHORTENER_REGEX = re.compile(r"(bit\.ly|goo\.gl|tinyurl|ow\.ly|t\.co|is\.gd|buff\.ly|rb\.gy|tiny\.cc)")

def _safe_get(url):
    """Requests GET with timeout and returns (response or None)."""
    try:
        return requests.get(url, timeout=REQUEST_TIMEOUT, allow_redirects=True)
    except Exception:
        return None

def _is_ip(host):
    try:
        socket.inet_aton(host)
        return True
    except Exception:
        return False

def _whois_lookup(domain):
    try:
        return whois.whois(domain)
    except Exception:
        return None

def _extract_domain_info(url):
    parsed = urlparse(url)
    netloc = parsed.netloc.split(':')[0]  # remove port
    extracted = tldextract.extract(url)
    root_domain = extracted.domain + ('.' + extracted.suffix if extracted.suffix else '')
    return parsed, netloc, extracted, root_domain

def _ratio_external_resources(soup, base_domain):
    """
    Compute ratio of resource links (img/script/link) hosted on external domains.
    Return ratio in [0,1]. If cannot compute, return None.
    """
    try:
        tags = []
        tags += [t.get('src') for t in soup.find_all('img') if t.get('src')]
        tags += [t.get('src') for t in soup.find_all('script') if t.get('src')]
        tags += [t.get('href') for t in soup.find_all('link') if t.get('href')]
        total = len(tags)
        if total == 0:
            return None
        external = 0
        for ref in tags:
            ref_parsed = urlparse(urljoin(base_domain, ref))
            host = ref_parsed.netloc.split(':')[0]
            if host and root_host(host) != root_host(base_domain):
                external += 1
        return external / total
    except Exception:
        return None

def root_host(host):
    """Return root host (domain + suffix) using tldextract for comparison."""
    try:
        e = tldextract.extract(host)
        return e.domain + ('.' + e.suffix if e.suffix else '')
    except Exception:
        return host

def get_url_features(url: str) -> dict:
    """
    Return a dict with the 30 features (excluding predicted_column).
    Values are in {-1, 0, 1}.
    """
    features = {}

    # Basic parsing
    parsed, netloc, extracted, root_domain = _extract_domain_info(url)
    host_no_port = netloc

    # Fetch page (if possible)
    resp = _safe_get(url)
    page_html = None
    soup = None
    if resp and resp.status_code == 200:
        try:
            page_html = resp.text
            soup = BeautifulSoup(page_html, "html.parser")
        except Exception:
            soup = None

    # ---------- 1. having_IP_Address ----------
    # -1 if IP address format used in host; 1 otherwise
    features["having_IP_Address"] = -1 if _is_ip(host_no_port) else 1

    # ---------- 2. URL_Length ----------
    L = len(url)
    if L < 54:
        features["URL_Length"] = 1
    elif 54 <= L <= 75:
        features["URL_Length"] = 0
    else:
        features["URL_Length"] = -1

    # ---------- 3. Shortining_Service ----------
    features["Shortining_Service"] = -1 if SHORTENER_REGEX.search(url) else 1

    # ---------- 4. having_At_Symbol ----------
    features["having_At_Symbol"] = -1 if "@" in url else 1

    # ---------- 5. double_slash_redirecting ----------
    # If '//' appears after the protocol part more than once -> suspicious
    # Protocol part 'http://' consumes first occurrence; count total occurrences in url
    features["double_slash_redirecting"] = -1 if url.count("//") > 1 else 1

    # ---------- 6. Prefix_Suffix (hyphen in domain) ----------
    features["Prefix_Suffix"] = -1 if "-" in extracted.domain else 1

    # ---------- 7. having_Sub_Domain ----------
    subdomain = extracted.subdomain
    if subdomain == "":
        features["having_Sub_Domain"] = 1
    else:
        # many levels (more than 2) suspicious
        if subdomain.count('.') == 0:
            # one level subdomain -> 0 (suspicious but sometimes normal)
            features["having_Sub_Domain"] = 0 if subdomain else 1
        elif subdomain.count('.') >= 1:
            features["having_Sub_Domain"] = -1

    # ---------- 8. SSLfinal_State ----------
    # 1 => legitimate (valid https & cert), -1 => phishing
    try:
        if url.startswith("https"):
            # If request succeeded and is https, regard as 1, otherwise -1
            features["SSLfinal_State"] = 1 if resp and resp.url.startswith("https") else -1
        else:
            features["SSLfinal_State"] = -1
    except Exception:
        features["SSLfinal_State"] = -1

    # ---------- WHOIS lookups (safe) ----------
    w = _whois_lookup(root_domain)

    # ---------- 9. Domain_registeration_length ----------
    try:
        exp = w.expiration_date
        if isinstance(exp, list):
            exp = exp[0]
        # If expiration date is datetime-like
        if isinstance(exp, datetime.datetime):
            days = (exp - datetime.datetime.now()).days
            features["Domain_registeration_length"] = 1 if days >= 365 else -1
        else:
            features["Domain_registeration_length"] = -1
    except Exception:
        features["Domain_registeration_length"] = -1

    # ---------- 10. Favicon ----------
    # If favicon is served from same domain -> 1, else -1
    try:
        fav = None
        if soup:
            icon = soup.find("link", rel=lambda v: v and ("icon" in v.lower()))
            if icon and icon.get("href"):
                fav = icon.get("href")
        if fav:
            fav_url = urljoin(url, fav)
            fav_host = urlparse(fav_url).netloc.split(':')[0]
            features["Favicon"] = 1 if root_host(fav_host) == root_host(host_no_port) else -1
        else:
            # no explicit favicon tag: neutral (0) — dataset sometimes uses 0
            features["Favicon"] = 0
    except Exception:
        features["Favicon"] = -1

    # ---------- 11. port ----------
    # 1 if default port (80 or 443) or none, -1 if suspicious custom port present
    try:
        if ":" in parsed.netloc:
            port = parsed.netloc.split(":")[-1]
            if port in ("80", "443"):
                features["port"] = 1
            else:
                features["port"] = -1
        else:
            features["port"] = 1
    except Exception:
        features["port"] = -1

    # ---------- 12. HTTPS_token ----------
    # -1 if 'https' token is present in domain part (attempt to trick)
    features["HTTPS_token"] = -1 if "https" in host_no_port.lower() else 1

    # ---------- 13. Request_URL ----------
    # Ratio of external object requests (images/scripts/links) — if > .61 suspicious => -1
    try:
        external_ratio = None
        if soup:
            refs = []
            refs += [t.get('src') for t in soup.find_all('img') if t.get('src')]
            refs += [t.get('src') for t in soup.find_all('script') if t.get('src')]
            refs += [t.get('href') for t in soup.find_all('link') if t.get('href')]
            refs = [r for r in refs if r]
            total = len(refs)
            if total == 0:
                external_ratio = None
            else:
                ext_count = 0
                for r in refs:
                    r_full = urljoin(url, r)
                    r_host = urlparse(r_full).netloc.split(':')[0]
                    if root_host(r_host) != root_host(host_no_port):
                        ext_count += 1
                external_ratio = ext_count / total
        if external_ratio is None:
            features["Request_URL"] = 1
        elif external_ratio < 0.22:
            features["Request_URL"] = 1
        elif 0.22 <= external_ratio <= 0.61:
            features["Request_URL"] = 0
        else:
            features["Request_URL"] = -1
    except Exception:
        features["Request_URL"] = -1

    # ---------- 14. URL_of_Anchor ----------
    # Ratio of anchors linking to external domains or javascript:void(0)/#
    try:
        if soup:
            anchors = [a.get('href') for a in soup.find_all('a') if a.get('href')]
            total = len(anchors)
            if total == 0:
                features["URL_of_Anchor"] = 1
            else:
                suspicious = 0
                for a in anchors:
                    href = a.strip()
                    if href.startswith('#') or href.lower().startswith('javascript'):
                        suspicious += 1
                    else:
                        full = urljoin(url, href)
                        if root_host(urlparse(full).netloc.split(':')[0]) != root_host(host_no_port):
                            suspicious += 1
                ratio = suspicious / total
                if ratio < 0.31:
                    features["URL_of_Anchor"] = 1
                elif 0.31 <= ratio <= 0.67:
                    features["URL_of_Anchor"] = 0
                else:
                    features["URL_of_Anchor"] = -1
        else:
            features["URL_of_Anchor"] = 1
    except Exception:
        features["URL_of_Anchor"] = -1

    # ---------- 15. Links_in_tags ----------
    # Similar check for <meta>, <link> tags pointing to external domains
    try:
        if soup:
            tags = [t.get('src') or t.get('href') for t in (soup.find_all(['meta', 'link'])) if (t.get('src') or t.get('href'))]
            total = len(tags)
            if total == 0:
                features["Links_in_tags"] = 1
            else:
                ext_count = 0
                for tval in tags:
                    full = urljoin(url, tval)
                    if root_host(urlparse(full).netloc.split(':')[0]) != root_host(host_no_port):
                        ext_count += 1
                ratio = ext_count / total
                if ratio < 0.17:
                    features["Links_in_tags"] = 1
                elif 0.17 <= ratio <= 0.81:
                    features["Links_in_tags"] = 0
                else:
                    features["Links_in_tags"] = -1
        else:
            features["Links_in_tags"] = 1
    except Exception:
        features["Links_in_tags"] = -1

    # ---------- 16. SFH (Server Form Handler) ----------
    # If forms exist and action attribute points to mailto or external domain => suspicious
    try:
        if soup:
            forms = soup.find_all('form')
            if len(forms) == 0:
                features["SFH"] = 1
            else:
                suspicious = 0
                for f in forms:
                    action = f.get('action')
                    if not action or action.strip() == "":
                        # empty action can be suspicious
                        suspicious += 1
                    else:
                        action_full = urljoin(url, action)
                        if action_full.lower().startswith("mailto:"):
                            suspicious += 1
                        else:
                            if root_host(urlparse(action_full).netloc.split(':')[0]) != root_host(host_no_port):
                                suspicious += 1
                ratio = suspicious / len(forms)
                # heuristic thresholds
                if ratio == 0:
                    features["SFH"] = 1
                elif 0 < ratio <= 0.5:
                    features["SFH"] = 0
                else:
                    features["SFH"] = -1
        else:
            features["SFH"] = 1
    except Exception:
        features["SFH"] = -1

    # ---------- 17. Submitting_to_email ----------
    features["Submitting_to_email"] = -1 if (page_html and "mailto:" in page_html.lower()) else 1

    # ---------- 18. Abnormal_URL ----------
    # If domain in URL is not root domain (i.e., domain portion doesn't match expected) -> suspicious
    try:
        # If netloc contains root_domain then ok else abnormal
        features["Abnormal_URL"] = 1 if root_host(host_no_port) == root_domain else -1
    except Exception:
        features["Abnormal_URL"] = -1

    # ---------- 19. Redirect ----------
    # Number of redirects in response history: >1 suspicious
    try:
        if resp is None:
            features["Redirect"] = -1
        else:
            redirs = len(resp.history)
            if redirs == 0:
                features["Redirect"] = 1
            elif redirs <= 2:
                features["Redirect"] = 0
            else:
                features["Redirect"] = -1
    except Exception:
        features["Redirect"] = -1

    # ---------- 20. on_mouseover ----------
    features["on_mouseover"] = -1 if (page_html and re.search(r"onmouseover\s*=", page_html, re.IGNORECASE)) else 1

    # ---------- 21. RightClick ----------
    # If right click disabled by script -> -1 else 1
    features["RightClick"] = -1 if (page_html and re.search(r"event.button ?== ?2|preventDefault\(|contextmenu", page_html, re.IGNORECASE)) else 1

    # ---------- 22. popUpWidnow ----------
    features["popUpWidnow"] = -1 if (page_html and re.search(r"window\.open\(", page_html, re.IGNORECASE)) else 1

    # ---------- 23. Iframe ----------
    try:
        if soup and soup.find_all('iframe'):
            features["Iframe"] = -1
        else:
            features["Iframe"] = 1
    except Exception:
        features["Iframe"] = -1

    # ---------- 24. age_of_domain ----------
    try:
        creation = None
        if w:
            creation = w.creation_date
            if isinstance(creation, list):
                creation = creation[0]
        if isinstance(creation, datetime.datetime):
            age_days = (datetime.datetime.now() - creation).days
            features["age_of_domain"] = 1 if age_days >= 180 else -1
        else:
            features["age_of_domain"] = -1
    except Exception:
        features["age_of_domain"] = -1

    # ---------- 25. DNSRecord ----------
    features["DNSRecord"] = 1 if w else -1

    # ---------- 26. web_traffic ----------
    # We cannot call Alexa/Similar unless API available; use heuristic: if HTTP status 200 -> 1, else -1
    try:
        if resp and resp.status_code == 200:
            features["web_traffic"] = 1
        else:
            features["web_traffic"] = -1
    except Exception:
        features["web_traffic"] = -1

    # ---------- 27. Page_Rank ----------
    # Placeholder: requires external API. We return 1 if site responds and is not tiny
    try:
        if resp and resp.status_code == 200 and len(resp.text) > 500:
            features["Page_Rank"] = 1
        else:
            features["Page_Rank"] = -1
    except Exception:
        features["Page_Rank"] = -1

    # ---------- 28. Google_Index ----------
    # Can't query Google here — heuristic: if site responded 200 -> 1 else -1
    try:
        features["Google_Index"] = 1 if (resp and resp.status_code == 200) else -1
    except Exception:
        features["Google_Index"] = -1

    # ---------- 29. Links_pointing_to_page ----------
    # Hard to compute accurately without backlink API; use heuristic:
    # if site has many external links to it (no data) => fallback -1 if WHOIS absent else 1
    try:
        features["Links_pointing_to_page"] = 1 if w else -1
    except Exception:
        features["Links_pointing_to_page"] = -1

    # ---------- 30. Statistical_report ----------
    # Placeholder: if many suspicious signals (count of -1s) => -1 else 1
    try:
        negatives = sum(1 for v in features.values() if v == -1)
        if negatives >= 8:
            features["Statistical_report"] = -1
        else:
            features["Statistical_report"] = 1
    except Exception:
        features["Statistical_report"] = -1

    # For traceability, ensure all expected keys exist and are ints
    expected_keys = [
        "having_IP_Address","URL_Length","Shortining_Service","having_At_Symbol",
        "double_slash_redirecting","Prefix_Suffix","having_Sub_Domain","SSLfinal_State",
        "Domain_registeration_length","Favicon","port","HTTPS_token","Request_URL",
        "URL_of_Anchor","Links_in_tags","SFH","Submitting_to_email","Abnormal_URL",
        "Redirect","on_mouseover","RightClick","popUpWidnow","Iframe","age_of_domain",
        "DNSRecord","web_traffic","Page_Rank","Google_Index","Links_pointing_to_page",
        "Statistical_report"
    ]
    for k in expected_keys:
        if k not in features:
            features[k] = -1

        # ensure integer
        try:
            features[k] = int(features[k])
        except Exception:
            features[k] = -1

    return features
