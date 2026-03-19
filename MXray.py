#!/usr/bin/env python3
import argparse
import asyncio
import csv
import json
import itertools
import sys
import re
import os
import time
import logging
from datetime import datetime
from typing import List, Dict, Optional, Set, Tuple
from collections import defaultdict, Counter
import uuid
import warnings
import socket

import dns.asyncresolver
import aiohttp

try:
    import resource
    # Maximize the open file limit on macOS/Linux
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    resource.setrlimit(resource.RLIMIT_NOFILE, (min(hard, 65536) if hard != resource.RLIM_INFINITY else 65536, hard))
except ImportError:
    pass # Windows doesn't have the resource module

# --------------------------------------------------------
# Config & Logging
# --------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s: %(message)s',
    handlers=[logging.StreamHandler()]
)

# Suppress harmless aiohttp warnings about illegal cookies from F5 load balancers
logging.getLogger("aiohttp.client").setLevel(logging.ERROR)

# Suppress harmless aiodns / pycares loop teardown warnings on macOS
warnings.filterwarnings("ignore", message="Exception ignored from cffi callback")


# Concurrency limits and Timeouts
QUERY_TIMEOUT = 5          # DNS lifetime per query (seconds)
DNS_CONCURRENCY = 500      # Max concurrent DNS queries (macOS friendly limit)
HTTP_CONCURRENCY = 80      # Max concurrent HTTP/site checks
SMTP_CONCURRENCY = 20      # Max concurrent SMTP catch-all probes
WHOIS_CONCURRENCY = 20     # Max concurrent WHOIS lookups
CONN_TIMEOUT = 5           # HTTP connection & read timeout - super aggressive for speed
SMTP_TIMEOUT = 8           # SMTP connect / read timeout
WHOIS_TIMEOUT = 8          # WHOIS connect / read timeout
MAX_HTML_SIZE = 128 * 1024 # Stop reading HTML after 128KB to avoid OOM
CHECK_WEBSITE = True       # Flip to False for DNS-only runs

PROCESS_ID = str(uuid.uuid4())[:8]

# Robust Public Resolvers (Google, Cloudflare, Quad9) defaults
PUBLIC_RESOLVERS = [
    '8.8.8.8', '8.8.4.4',
    '1.1.1.1', '1.0.0.1',
    '9.9.9.9', '149.112.112.112'
]

# --------------------------------------------------------
# Simple in-memory LRU caches
# --------------------------------------------------------

class LRUCache:
    def __init__(self, capacity: int = 10000):
        self.capacity = capacity
        self.cache: Dict[str, object] = {}
        self.order: List[str] = []

    def get(self, key: str):
        if key in self.cache:
            self.order.remove(key)
            self.order.append(key)
            return self.cache[key]
        return None

    def set(self, key: str, value):
        if key in self.cache:
            self.cache[key] = value
            self.order.remove(key)
            self.order.append(key)
            return
        if len(self.cache) >= self.capacity:
            oldest = self.order.pop(0)
            del self.cache[oldest]
        self.cache[key] = value
        self.order.append(key)


DNS_CACHE = LRUCache(100000)
WEBSITE_CACHE = LRUCache(50000)
DOMAIN_RESULT_CACHE = LRUCache(500000)
WHOIS_CACHE = LRUCache(100000)

# --------------------------------------------------------
# Typo detection helper (Damerau-Levenshtein distance 1)
# --------------------------------------------------------

def _is_one_edit_away(a: str, b: str) -> bool:
    """True if a and b differ by exactly 1 insertion, deletion,
    substitution, or adjacent transposition."""
    la, lb = len(a), len(b)
    if abs(la - lb) > 1:
        return False

    if la == lb:
        # Substitution or adjacent transposition
        diffs = [i for i in range(la) if a[i] != b[i]]
        if len(diffs) == 1:
            return True  # single substitution
        if len(diffs) == 2 and diffs[1] == diffs[0] + 1:
            # adjacent transposition
            return a[diffs[0]] == b[diffs[1]] and a[diffs[1]] == b[diffs[0]]
        return False

    # Insertion / deletion: longer string has exactly one extra char
    longer, shorter = (a, b) if la > lb else (b, a)
    i = j = 0
    edits = 0
    while i < len(longer) and j < len(shorter):
        if longer[i] != shorter[j]:
            edits += 1
            if edits > 1:
                return False
            i += 1  # skip the extra char in the longer string
        else:
            i += 1
            j += 1
    return True


# --------------------------------------------------------
# Analyzer
# --------------------------------------------------------

class EmailDomainAnalyzer:
    def __init__(self, enable_catch_all: bool = False, check_website: bool = CHECK_WEBSITE, enable_whois: bool = False):
        self.dns_semaphore = asyncio.Semaphore(DNS_CONCURRENCY)
        self.http_semaphore = asyncio.Semaphore(HTTP_CONCURRENCY)
        self.smtp_semaphore = asyncio.Semaphore(SMTP_CONCURRENCY)
        self.whois_semaphore = asyncio.Semaphore(WHOIS_CONCURRENCY)
        
        self.session: Optional[aiohttp.ClientSession] = None
        self.resolver = None
        self.enable_catch_all = enable_catch_all
        self.check_website_enabled = check_website
        self.enable_whois = enable_whois
        self.smtp_helo_name = socket.getfqdn() or "localhost"
        self.smtp_probe_from = "probe@example.com"
        
        self.logger = logging.getLogger(__name__)
        self.failed_website_cache = LRUCache(5000)
        self.rules = self.load_rules()
        self.allowlisted_domains = self.load_simple_domain_file("domain_allowlist.csv")
        suppression_domains = self.load_simple_domain_file("domain_suppressions.csv")
        known_bad_domains = self.load_simple_domain_file("domain_known_bad.csv")
        self.known_bad_domains = suppression_domains | known_bad_domains
        self.history_path = os.path.join(os.path.dirname(__file__), "mxray_history.jsonl")
        self.history_cache = self.load_history_index()

        # Disposable / throwaway email MX patterns
        # Consolidated from spamtrap_rules.json, swissarmydomain.py v1, and manual research
        self.DISPOSABLE_MX_PATTERNS = [
            # Erinn spam trap network
            "erinn.biz", "erinn-email.org",
            # Classic disposable providers
            "mailinator.com", "mail.mailinator.com", "mail2.mailinator.com",
            "10minutemail.com", "prd-smtp.10minutemail.com",
            "guerrillamail.com", "trashmail.com", "tempmail.com",
            "yopmail.com", "dispostable.com", "maildrop.cc",
            "getnada.com", "temp-mail.org", "emailondeck.com",
            "throwawaymail.com", "sharklasers.com", "grr.la",
            "mailcatch.com", "tempail.com", "tempm.com", "moakt.com",
            # Fake email generators
            "email-fake.com", "emailfake.com", "generator.email",
            # One-time / temp mail services
            "in.mail.tm", "mail.onetimemail.org",
            # Known trap-adjacent infrastructure
            "mail.haoo.com", "mail.wabblywabble.com", "mail.wallywatts.com",
            "hubblehost.com",
        ]

        # Known trap / suspicious MX infrastructure
        # These are specific MX hostnames seen on spam trap and honeypot domains
        self.TRAP_MX_PATTERNS = [
            # Erinn recv hosts
            "recv1.erinn.biz", "recv2.erinn.biz", "recv3.erinn.biz",
            "recv4.erinn.biz", "recv6.erinn.biz", "recv7.erinn.biz",
            "recv8.erinn.biz", "recv100.erinn.biz", "recv101.erinn.biz",
            # Other known trap infrastructure
            "h-email.net", "mx.mail-data.net",
            "mx1-hosting.jellyfish.systems", "mx2-hosting.jellyfish.systems",
            "mx3-hosting.jellyfish.systems",
            "mx1.emaildbox.pro", "mx2.emaildbox.pro", "mx3.emaildbox.pro",
            "mx4.emaildbox.pro", "mx5.emaildbox.pro",
            # Catch-all trap servers
            "catchservers.net", "catchservers.com",
            "brushemail.com",
        ]

        # Specific MX providers known for parking
        self.PARKED_MX_PATTERNS = [
            "park-mx.above.com",
            "sedoparking.com", "parkingcrew.net",
            "bodis.com", "fabulous.com",
        ]

        # Domain parking infrastructure usually points NS here
        self.PARKED_NS_PATTERNS = [
            "sedoparking.com", "bodis.com", "namebrightdns.com",
            "parkingcrew.net", "vparking.com", "domainparkingserver.net",
            "fabulous.com", "cashparking.com", "smartname.com",
            "domainnamesales.com", "uniregistrymarket.link",
            "parklogic.com", "dns.parkpage.foundationapi.com"
        ]

        self.parking_regexes = [
            re.compile(r'\b' + re.escape(k) + r'\b') for k in [
                "this domain is parked", "domain for sale", "buy this domain",
                "this domain may be for sale", "parkingcrew", "afternic",
                "hugedomains", "this web page is parked", "domain is available",
                "domain names for sale", "buy domain", "sale domain", "sedo domain",
                "inquire about this domain", "this domain is registered", "lb_check"
            ]
        ]
        
        self.medical_regexes = [
            re.compile(r'\b' + re.escape(k) + r'\b') for k in [
                "hospital", "healthcare", "health care", "behavioral health",
                "patient", "physician", "doctor", "clinic", "medical center",
                "psychiatric", "mental health", "pediatrics", "surgery"
            ]
        ]
        
        self.spam_regexes = [
            re.compile(r'\b' + re.escape(k) + r'\b') for k in [
                "betting sites", "online casino", "slot machines", "sports betting",
                "play roulette", "real money casino", "online betting", "sportsbook",
                "casino bonus"
            ]
        ]

        # ----- Role account detection -----
        self.ROLE_ACCOUNTS = {
            "info", "admin", "administrator", "postmaster", "abuse",
            "webmaster", "hostmaster", "sales", "support", "contact",
            "help", "office", "billing", "accounts", "noreply",
            "no-reply", "mailer-daemon", "marketing", "newsletter",
            "subscribe", "unsubscribe", "feedback", "media", "press",
            "security", "compliance", "legal", "hr", "jobs", "careers",
            "reception", "registrar", "root", "ftp", "www", "mail",
            "list", "listserv", "majordomo", "owner",
        }

        # ----- Disposamail / stuffed address pattern (per Spamhaus guidance) -----
        # Exactly 10 characters: 5-7 letters followed by 3-5 numbers, domain usually .com
        self.DISPOSAMAIL_REGEX = re.compile(r'^[a-z]{5,7}[0-9]{3,5}$')

        # ----- Typo detection: canonical consumer mailbox domains (MAGY 2025) -----
        # Legitimate domains that happen to be within edit distance 1 of a MAGY domain
        self.TYPO_EXEMPT_DOMAINS = {
            "mail.com", "gmx.com", "gmx.net", "gmx.de",
            "aim.com",   # 1 edit from aol.com but is a real Yahoo property
        }

        # MAGY 2025 canonical consumer mailbox domains
        # Source: Al Iverson's Microsoft/Apple/Google/Yahoo reference (April 2025)
        self.CANONICAL_CONSUMER_DOMAINS = {
            # Google (2)
            "gmail.com", "googlemail.com",
            # Apple (3)
            "icloud.com", "mac.com", "me.com",
            # Microsoft (168)
            "hotmail.ac", "hotmail.as", "hotmail.at", "hotmail.ba", "hotmail.bb",
            "hotmail.be", "hotmail.bs", "hotmail.ca", "hotmail.ch", "hotmail.cl",
            "hotmail.co.at", "hotmail.co.id", "hotmail.co.il", "hotmail.co.in",
            "hotmail.co.jp", "hotmail.co.kr", "hotmail.co.nz", "hotmail.co.pn",
            "hotmail.co.th", "hotmail.co.ug", "hotmail.co.uk", "hotmail.co.ve",
            "hotmail.co.za", "hotmail.com", "hotmail.com.ar", "hotmail.com.au",
            "hotmail.com.bo", "hotmail.com.br", "hotmail.com.do", "hotmail.com.hk",
            "hotmail.com.ly", "hotmail.com.my", "hotmail.com.ph", "hotmail.com.pl",
            "hotmail.com.ru", "hotmail.com.sg", "hotmail.com.tr", "hotmail.com.tt",
            "hotmail.com.tw", "hotmail.com.uz", "hotmail.com.ve", "hotmail.com.vn",
            "hotmail.de", "hotmail.dk", "hotmail.ee", "hotmail.es", "hotmail.fi",
            "hotmail.fr", "hotmail.gr", "hotmail.hk", "hotmail.hu", "hotmail.ie",
            "hotmail.it", "hotmail.jp", "hotmail.la", "hotmail.lt", "hotmail.lu",
            "hotmail.lv", "hotmail.ly", "hotmail.mn", "hotmail.mw", "hotmail.my",
            "hotmail.net.fj", "hotmail.no", "hotmail.ph", "hotmail.pn", "hotmail.pt",
            "hotmail.rs", "hotmail.se", "hotmail.sg", "hotmail.sh", "hotmail.sk",
            "hotmail.ua", "hotmail.vu",
            "live.at", "live.be", "live.ca", "live.ch", "live.cl", "live.cn",
            "live.co.in", "live.co.kr", "live.co.uk", "live.co.za", "live.com",
            "live.com.ar", "live.com.au", "live.com.co", "live.com.mx", "live.com.my",
            "live.com.pe", "live.com.ph", "live.com.pk", "live.com.pt", "live.com.sg",
            "live.com.ve", "live.de", "live.dk", "live.fi", "live.fr", "live.hk",
            "live.ie", "live.in", "live.it", "live.jp", "live.nl", "live.no",
            "live.ph", "live.ru", "live.se",
            "msn.com", "msn.nl",
            "outlook.at", "outlook.be", "outlook.bg", "outlook.bz", "outlook.cl",
            "outlook.cm", "outlook.co", "outlook.co.cr", "outlook.co.id",
            "outlook.co.il", "outlook.co.nz", "outlook.co.th", "outlook.com",
            "outlook.com.ar", "outlook.com.au", "outlook.com.br", "outlook.com.es",
            "outlook.com.gr", "outlook.com.hr", "outlook.com.pe", "outlook.com.py",
            "outlook.com.tr", "outlook.com.ua", "outlook.com.vn", "outlook.cz",
            "outlook.de", "outlook.dk", "outlook.ec", "outlook.es", "outlook.fr",
            "outlook.hn", "outlook.ht", "outlook.hu", "outlook.ie", "outlook.in",
            "outlook.it", "outlook.jp", "outlook.kr", "outlook.la", "outlook.lv",
            "outlook.mx", "outlook.my", "outlook.pa", "outlook.ph", "outlook.pk",
            "outlook.pt", "outlook.ro", "outlook.sa", "outlook.sg", "outlook.si",
            "outlook.sk", "outlook.uy",
            "passport.com", "webtv.net", "windowslive.com", "windowslive.es",
            # Yahoo / AOL (128)
            "aim.com", "aol.at", "aol.be", "aol.ch", "aol.cl", "aol.co.nz",
            "aol.co.uk", "aol.com", "aol.com.ar", "aol.com.au", "aol.com.br",
            "aol.com.co", "aol.com.mx", "aol.com.tr", "aol.com.ve", "aol.cz",
            "aol.de", "aol.dk", "aol.es", "aol.fi", "aol.fr", "aol.hk", "aol.in",
            "aol.it", "aol.jp", "aol.kr", "aol.nl", "aol.pl", "aol.ru", "aol.se",
            "aol.tw", "aolchina.com", "aolnews.com", "aolvideo.com",
            "aprilshowersflorists.com", "asylum.com", "bellatlantic.net",
            "bloomoffaribault.com", "citlink.net", "compuserve.com", "cox.net",
            "cs.com", "csi.com", "dogsinthenews.com", "epix.net", "frontier.com",
            "frontiernet.net", "geocities.com", "goowy.com", "gte.net", "kimo.com",
            "lemondrop.com", "mcom.com", "myfrontiermail.com", "myyahoo.com",
            "netbusiness.com", "netscape.com", "netscape.net", "newnorth.net",
            "robertgillingsproductions.com", "rocketmail.com", "rogers.com",
            "safesocial.com", "simivalleyflowers.com", "sky.com", "spinner.com",
            "switched.com", "urlesque.com", "verizon.net", "vincentthepoet.com",
            "when.com", "wild4music.com", "wmconnect.com", "wow.com", "y7mail.com",
            "yahoo.at", "yahoo.be", "yahoo.bg", "yahoo.ca", "yahoo.cl",
            "yahoo.co.id", "yahoo.co.il", "yahoo.co.in", "yahoo.co.kr",
            "yahoo.co.nz", "yahoo.co.th", "yahoo.co.uk", "yahoo.co.za",
            "yahoo.com", "yahoo.com.ar", "yahoo.com.au", "yahoo.com.br",
            "yahoo.com.co", "yahoo.com.hk", "yahoo.com.hr", "yahoo.com.mx",
            "yahoo.com.my", "yahoo.com.pe", "yahoo.com.ph", "yahoo.com.sg",
            "yahoo.com.tr", "yahoo.com.tw", "yahoo.com.ua", "yahoo.com.ve",
            "yahoo.com.vn", "yahoo.cz", "yahoo.de", "yahoo.dk", "yahoo.ee",
            "yahoo.es", "yahoo.fi", "yahoo.fr", "yahoo.gr", "yahoo.hu",
            "yahoo.ie", "yahoo.in", "yahoo.it", "yahoo.lt", "yahoo.lv",
            "yahoo.nl", "yahoo.no", "yahoo.pl", "yahoo.pt", "yahoo.ro",
            "yahoo.se", "yahoo.sk", "ygm.com", "ymail.com",
        }

        # Index by TLD for fast lookup
        self._canonical_by_tld: Dict[str, List[str]] = {}
        for d in self.CANONICAL_CONSUMER_DOMAINS:
            tld = d.rsplit(".", 1)[-1]
            self._canonical_by_tld.setdefault(tld, []).append(d)

        self.cache_hits = 0
        self.cache_misses = 0

    def load_rules(self) -> dict:
        rules_path = os.path.join(os.path.dirname(__file__), "mx_rules.json")
        fallback_path = os.path.join(os.path.dirname(__file__), "spamtrap_rules.json")
        for path in [rules_path, fallback_path]:
            try:
                with open(path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                data["_source"] = path
                return data
            except FileNotFoundError:
                continue
            except Exception as e:
                self.logger.warning(f"Failed to load rules from {path}: {e}")
        return {"mx_provider_rules": [], "risk_band_thresholds": {"high": 60, "medium": 30}, "_source": "built-in"}

    def load_simple_domain_file(self, filename: str) -> Set[str]:
        path = os.path.join(os.path.dirname(__file__), filename)
        domains: Set[str] = set()
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                for raw in f:
                    line = raw.strip().lower()
                    if not line or line.startswith("#"):
                        continue
                    first = line.split(",")[0].strip()
                    domain = self.extract_domain(first) if ("@" in first or "." in first) else None
                    if domain:
                        domains.add(domain)
        except FileNotFoundError:
            return set()
        except Exception as e:
            self.logger.warning(f"Failed loading {filename}: {e}")
        return domains

    def load_history_index(self) -> Dict[str, dict]:
        history: Dict[str, dict] = {}
        try:
            with open(self.history_path, "r", encoding="utf-8", errors="replace") as f:
                for raw in f:
                    raw = raw.strip()
                    if not raw:
                        continue
                    try:
                        record = json.loads(raw)
                    except json.JSONDecodeError:
                        continue
                    domain = str(record.get("domain", "")).lower()
                    if domain:
                        history[domain] = record
        except FileNotFoundError:
            return {}
        except Exception as e:
            self.logger.warning(f"Failed loading history index: {e}")
        return history

    async def setup(self):
        if self.session is None:
            # Connection pooling for high concurrency
            connector = aiohttp.TCPConnector(limit=HTTP_CONCURRENCY, ttl_dns_cache=300, ssl=False)
            timeout = aiohttp.ClientTimeout(total=CONN_TIMEOUT, connect=CONN_TIMEOUT)
            self.session = aiohttp.ClientSession(connector=connector, timeout=timeout)
            
        if self.resolver is None:
            self.resolver = dns.asyncresolver.Resolver(configure=False)
            self.resolver.nameservers = PUBLIC_RESOLVERS
            self.resolver.timeout = QUERY_TIMEOUT
            self.resolver.lifetime = QUERY_TIMEOUT

        # DNS self-test
        mx = await self.check_mx("gmail.com")
        a = await self.check_a("gmail.com")
        if not mx and not a:
            raise RuntimeError(
                "DNS self-test failed: gmail.com has no MX or A via asyncresolver "
                "(resolver / network problem)"
            )
        print(f"\n✅ DNS self-test OK: gmail.com MX={bool(mx)} A={bool(a)}\n")

    async def cleanup(self):
        if self.session:
            await self.session.close()
            self.session = None

    # ----------------- I/O helpers -----------------

    def extract_domain(self, entry: str) -> Optional[str]:
        entry = entry.strip()
        if '@' in entry and not entry.startswith('@'):
            return entry.split('@')[-1].lower()
        if re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', entry):
            return entry.lower()
        return None

    def generate_output_filename(self, input_file: str) -> str:
        base, _ = os.path.splitext(input_file)
        ts = datetime.now().strftime('%Y%m%d_%H%M%S')
        return f"{base}_analysis_{ts}_{PROCESS_ID}.csv"

    def detect_email_column(self, header: List[str], peek_row: Optional[list]) -> Tuple[int, str]:
        if not header:
            return 0, ""

        normalized = [str(col).lower().strip() for col in header]

        exact_candidates = [
            "email", "e-mail", "email_address", "email address",
            "recipient", "recipient_email", "recipient email",
            "envelope.targets", "envelope.target",
            "mailingList.address".lower()
        ]
        for candidate in exact_candidates:
            if candidate in normalized:
                return normalized.index(candidate), header[normalized.index(candidate)]

        domain_candidates = [
            "recipientdomain", "recipient_domain", "recipient domain",
            "domain", "domain.name"
        ]
        for candidate in domain_candidates:
            if candidate in normalized:
                return normalized.index(candidate), header[normalized.index(candidate)]

        weighted_contains = [
            ("recipient", 100),
            ("target", 90),
            ("email", 80),
            ("domain", 40),
            ("sender", -50),
            ("from", -30),
            ("envelope.sender", -80),
        ]
        best_index = -1
        best_score = -10**9
        for i, col in enumerate(normalized):
            score = 0
            for token, weight in weighted_contains:
                if token in col:
                    score += weight
            if score > best_score:
                best_score = score
                best_index = i
        if best_index >= 0 and best_score > 0:
            return best_index, header[best_index]

        if peek_row:
            for i, val in enumerate(peek_row):
                if '@' in str(val):
                    return i, header[i] if i < len(header) else ""
            for i, val in enumerate(peek_row):
                if self.extract_domain(str(val)):
                    return i, header[i] if i < len(header) else ""

        return 0, header[0]

    # ----------------- DNS: MX / A / TXT (SPF/DMARC) / NS -----------------

    async def _resolve_with_retry(self, domain: str, qtype: str, max_retries: int = 2):
        import dns.resolver
        for attempt in range(max_retries + 1):
            try:
                if attempt > 0:
                    await asyncio.sleep(0.5 * attempt)
                return await self.resolver.resolve(domain, qtype)
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
                raise
            except Exception as e:
                if attempt == max_retries:
                    raise

    async def check_mx(self, domain: str) -> List[str]:
        key = f"mx:{domain}"
        cached = DNS_CACHE.get(key)
        if cached is not None:
            self.cache_hits += 1
            return cached

        self.cache_misses += 1
        async with self.dns_semaphore:
            try:
                ans = await self._resolve_with_retry(domain, 'MX')
                raw = sorted(str(r.exchange).rstrip('.') for r in ans)
                # Filter out null MX records (RFC 7505): "MX 0 ." means
                # "this domain does not accept mail". dnspython returns
                # the exchange as "" or "." after stripping.
                records = [r for r in raw if r and r != '.']
                # If the ONLY record was a null MX, flag it explicitly
                if not records and raw:
                    records = ["NULL-MX"]
            except Exception as e:
                # Log actual DNS failures unless they are simple NXDOMAIN
                if "NXDOMAIN" not in str(e) and "NoAnswer" not in str(e):
                    self.logger.debug(f"MX lookup failed for {domain}: {type(e).__name__} {e}")
                records = []

        DNS_CACHE.set(key, records)
        return records

    async def check_a(self, domain: str) -> List[str]:
        key = f"a:{domain}"
        cached = DNS_CACHE.get(key)
        if cached is not None:
            self.cache_hits += 1
            return cached

        self.cache_misses += 1
        async with self.dns_semaphore:
            try:
                ans = await self._resolve_with_retry(domain, 'A')
                records = sorted(str(r.address) for r in ans)
            except Exception as e:
                if "NXDOMAIN" not in str(e) and "NoAnswer" not in str(e):
                    self.logger.debug(f"A lookup failed for {domain}: {type(e).__name__} {e}")
                records = []

        DNS_CACHE.set(key, records)
        return records

    async def check_ns(self, domain: str) -> List[str]:
        key = f"ns:{domain}"
        cached = DNS_CACHE.get(key)
        if cached is not None:
            self.cache_hits += 1
            return cached

        self.cache_misses += 1
        async with self.dns_semaphore:
            try:
                ans = await self._resolve_with_retry(domain, 'NS')
                records = sorted(str(r.target).rstrip('.') for r in ans)
            except Exception as e:
                if "NXDOMAIN" not in str(e) and "NoAnswer" not in str(e):
                    self.logger.debug(f"NS lookup failed for {domain}: {type(e).__name__} {e}")
                records = []

        DNS_CACHE.set(key, records)
        return records

    async def check_txt(self, domain: str, record_type: str) -> Optional[str]:
        key = f"txt:{record_type}:{domain}"
        cached = DNS_CACHE.get(key)
        if cached is not None:
            self.cache_hits += 1
            return cached

        self.cache_misses += 1
        async with self.dns_semaphore:
            try:
                ans = await self._resolve_with_retry(domain, 'TXT')
                for r in ans:
                    txt = ''.join(s.decode("utf-8") if isinstance(s, bytes) else str(s) for s in r.strings)
                    if record_type == "spf" and "v=spf1" in txt:
                        DNS_CACHE.set(key, txt)
                        return txt
                    if record_type == "dmarc" and "v=DMARC1" in txt:
                        DNS_CACHE.set(key, txt)
                        return txt
            except Exception as e:
                if "NXDOMAIN" not in str(e) and "NoAnswer" not in str(e):
                    self.logger.debug(f"TXT {record_type} lookup failed for {domain}: {type(e).__name__} {e}")

        DNS_CACHE.set(key, None)
        return None
        
    def get_organizational_domain(self, domain: str) -> str:
        parts = domain.split('.')
        if len(parts) <= 2:
            return domain
            
        # Common second-level domains for ccTLDs
        slds = {
            'com', 'co', 'org', 'net', 'edu', 'gov', 'ac', 'mil', 'sch', 'or', 
            'sld', 'gob', 'gub', 'go', 'ne', 'pe', 'res'
        }
        
        if len(parts) >= 3 and parts[-2] in slds and len(parts[-1]) == 2:
            return f"{parts[-3]}.{parts[-2]}.{parts[-1]}"
        
        return f"{parts[-2]}.{parts[-1]}"

    async def get_dmarc(self, domain: str) -> Optional[str]:
        # Implementation of cascading DMARC
        dmarc_record = await self.check_txt(f"_dmarc.{domain}", 'dmarc')
        if dmarc_record:
            return dmarc_record
            
        org_domain = self.get_organizational_domain(domain)
        if org_domain and org_domain != domain:
            return await self.check_txt(f"_dmarc.{org_domain}", 'dmarc')
        return None


    def _registered_domainish(self, hostname: str) -> str:
        parts = hostname.lower().strip(".").split(".")
        if len(parts) <= 2:
            return hostname.lower().strip(".")
        if len(parts[-1]) == 2 and parts[-2] in {"co", "com", "org", "net", "gov", "ac"} and len(parts) >= 3:
            return ".".join(parts[-3:])
        return ".".join(parts[-2:])

    def analyze_mx_infrastructure(self, mx_records: List[str]) -> dict:
        if not mx_records:
            return {
                "mx_category": "No MX",
                "mx_provider": "No MX",
                "mx_family": "",
                "mx_risk_tier": "none",
                "mx_signal_flags": "",
                "mx_rule_weight": 0
            }

        matched_rule = None
        matched_host = ""
        rules = self.rules.get("mx_provider_rules", [])
        for mx in mx_records:
            mx_lower = mx.lower()
            for rule in rules:
                patterns = rule.get("patterns", [])
                if any(mx_lower.endswith(pat) or pat in mx_lower for pat in patterns):
                    matched_rule = rule
                    matched_host = mx
                    break
            if matched_rule:
                break

        if matched_rule:
            flags = list(matched_rule.get("flags", []))
            if matched_host:
                flags.append(f"matched:{matched_host.lower()}")
            return {
                "mx_category": matched_rule.get("category", matched_rule.get("name", "Custom")),
                "mx_provider": matched_rule.get("name", "Custom"),
                "mx_family": matched_rule.get("family", self._registered_domainish(matched_host)),
                "mx_risk_tier": matched_rule.get("risk_tier", "contextual"),
                "mx_signal_flags": " | ".join(flags),
                "mx_rule_weight": int(matched_rule.get("risk_weight", 0))
            }

        families = sorted({self._registered_domainish(mx) for mx in mx_records if mx and mx != "NULL-MX"})
        primary_family = families[0] if families else ""
        inferred_flags: List[str] = []
        tier = "contextual"
        category = "Custom"
        provider = "Custom"
        weight = 5

        if any("forward" in mx.lower() or "route" in mx.lower() or "alias" in mx.lower() for mx in mx_records):
            inferred_flags.append("forwarding-like")
            tier = "elevated"
            weight = 20
        if len(families) > 1:
            inferred_flags.append("multi-family-mx")
            tier = "elevated"
            weight = max(weight, 12)
        if primary_family:
            inferred_flags.append(f"family:{primary_family}")

        return {
            "mx_category": category,
            "mx_provider": provider,
            "mx_family": primary_family,
            "mx_risk_tier": tier,
            "mx_signal_flags": " | ".join(inferred_flags),
            "mx_rule_weight": weight
        }

    async def get_domain_dns(self, domain: str) -> dict:
        mx_records, a_records, ns_records, spf_record, dmarc_record = await asyncio.gather(
            self.check_mx(domain),
            self.check_a(domain),
            self.check_ns(domain),
            self.check_txt(domain, 'spf'),
            self.get_dmarc(domain)
        )

        mx_intel = self.analyze_mx_infrastructure(mx_records)
        return {
            "domain": domain,
            "mx_records": mx_records,
            "mx_category": mx_intel["mx_category"],
            "mx_provider": mx_intel["mx_provider"],
            "mx_family": mx_intel["mx_family"],
            "mx_risk_tier": mx_intel["mx_risk_tier"],
            "mx_signal_flags": mx_intel["mx_signal_flags"],
            "mx_rule_weight": mx_intel["mx_rule_weight"],
            "a_records": a_records,
            "ns_records": ns_records,
            "spf_record": spf_record,
            "dmarc_record": dmarc_record,
            "has_mx": bool(mx_records),
            "has_a": bool(a_records),
            "has_ns": bool(ns_records),
            "has_spf": spf_record is not None,
            "has_dmarc": dmarc_record is not None
        }


    # ----------------- Website checking (Async String Search) -----------------

    async def check_website(self, domain: str) -> dict:
        cached = WEBSITE_CACHE.get(domain)
        if cached:
            self.cache_hits += 1
            return cached

        failed = self.failed_website_cache.get(domain)
        if failed:
            return failed

        self.cache_misses += 1
        async with self.http_semaphore:
            try:
                async with self.session.get(f"http://{domain}", allow_redirects=True) as resp:
                    redirect_url = str(resp.url) if resp.history else ""
                    
                    if resp.status >= 400:
                        result = {"status": "error", "details": f"HTTP {resp.status}", "redirect_url": redirect_url}
                        self.failed_website_cache.set(domain, result)
                        WEBSITE_CACHE.set(domain, result)
                        return result
                    
                    # Read streaming payload to avoid loading 100MB videos into memory
                    content_bytes = bytearray()
                    async for chunk in resp.content.iter_chunked(1024 * 64):
                        content_bytes.extend(chunk)
                        if len(content_bytes) > MAX_HTML_SIZE:
                            break # We have enough text to find a parking phrase 

                    text = content_bytes.decode('utf-8', errors='ignore').lower()
                    
                    if any(regex.search(text) for regex in self.parking_regexes):
                        result = {"status": "parked", "details": "Domain appears parked/for sale via HTTP", "redirect_url": redirect_url}
                        self.failed_website_cache.set(domain, result)
                        WEBSITE_CACHE.set(domain, result)
                        return result
                        
                    if any(regex.search(text) for regex in self.spam_regexes):
                        # If it has gambling spam but also medical terms, it's likely a hacked hospital/clinic
                        if any(regex.search(text) for regex in self.medical_regexes):
                            result = {"status": "spam", "details": "Hacked/Compromised Medical Website (SEO Spam detected)", "redirect_url": redirect_url}
                        else:
                            result = {"status": "spam", "details": "Website appears to be SEO spam / gambling", "redirect_url": redirect_url}
                        self.failed_website_cache.set(domain, result)
                        WEBSITE_CACHE.set(domain, result)
                        return result
                    
                result = {"status": "live", "details": f"HTTP {resp.status}", "redirect_url": redirect_url}
                WEBSITE_CACHE.set(domain, result)
                return result
            except Exception as e:
                result = {"status": "dead", "details": str(e), "redirect_url": ""}
                self.failed_website_cache.set(domain, result)
                WEBSITE_CACHE.set(domain, result)
                return result

    # ----------------- WHOIS Registry Checking (Port 43) -----------------

    async def _whois_query(self, server: str, query: str) -> str:
        reader = None
        writer = None
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(server, 43),
                timeout=WHOIS_TIMEOUT
            )
            writer.write((query + "\r\n").encode("utf-8", errors="ignore"))
            await asyncio.wait_for(writer.drain(), timeout=WHOIS_TIMEOUT)

            chunks = []
            while True:
                chunk = await asyncio.wait_for(reader.read(4096), timeout=WHOIS_TIMEOUT)
                if not chunk:
                    break
                chunks.append(chunk)
            return b"".join(chunks).decode("utf-8", errors="ignore")
        finally:
            if writer is not None:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass

    def _parse_whois_server(self, response: str) -> str:
        for line in response.splitlines():
            if ":" not in line:
                continue
            key, value = line.split(":", 1)
            if key.strip().lower() in ("refer", "whois", "whois server"):
                return value.strip()
        return ""

    def _parse_whois_created_at(self, response: str) -> Optional[datetime]:
        patterns = [
            r"(?im)^creation date:\s*(.+)$",
            r"(?im)^created on:\s*(.+)$",
            r"(?im)^created:\s*(.+)$",
            r"(?im)^registered on:\s*(.+)$",
            r"(?im)^domain registration date:\s*(.+)$",
            r"(?im)^registration time:\s*(.+)$"
        ]
        for pattern in patterns:
            m = re.search(pattern, response)
            if not m:
                continue
            raw = m.group(1).strip()
            cleaned = raw.replace("(UTC)", "").replace("Z", "+00:00")
            for fmt in (
                None,
                "%Y-%m-%d",
                "%Y-%m-%d %H:%M:%S",
                "%Y-%m-%d %H:%M:%S%z",
                "%d-%b-%Y",
                "%Y.%m.%d",
                "%d.%m.%Y %H:%M:%S",
                "%Y/%m/%d",
            ):
                try:
                    dt = datetime.fromisoformat(cleaned) if fmt is None else datetime.strptime(cleaned, fmt)
                    return dt
                except Exception:
                    continue
        return None

    async def check_whois(self, domain: str) -> dict:
        if not self.enable_whois:
            return {
                "domain_age": "Unknown",
                "domain_created_at": "",
                "domain_age_days": "",
                "whois_status": "skipped",
                "whois_details": "WHOIS disabled"
            }

        cache_key = f"whois:{domain}"
        cached = WHOIS_CACHE.get(cache_key)
        if cached is not None:
            self.cache_hits += 1
            return cached

        self.cache_misses += 1
        async with self.whois_semaphore:
            try:
                tld = domain.rsplit(".", 1)[-1].lower()
                iana_resp = await self._whois_query("whois.iana.org", tld)
                whois_server = self._parse_whois_server(iana_resp)
                if not whois_server:
                    result = {
                        "domain_age": "Unknown",
                        "domain_created_at": "",
                        "domain_age_days": "",
                        "whois_status": "unsupported",
                        "whois_details": f"No WHOIS server found for .{tld}"
                    }
                else:
                    resp = await self._whois_query(whois_server, domain)
                    created_at = self._parse_whois_created_at(resp)
                    if created_at is None:
                        result = {
                            "domain_age": "Unknown",
                            "domain_created_at": "",
                            "domain_age_days": "",
                            "whois_status": "unparsed",
                            "whois_details": f"WHOIS response from {whois_server} did not include a parseable creation date"
                        }
                    else:
                        now = datetime.utcnow()
                        if created_at.tzinfo is not None:
                            created_naive = created_at.astimezone().replace(tzinfo=None)
                        else:
                            created_naive = created_at
                        age_days = max((now - created_naive).days, 0)
                        age_years = age_days // 365
                        age_months = (age_days % 365) // 30
                        result = {
                            "domain_age": f"{age_years} Years, {age_months} Months",
                            "domain_created_at": created_naive.strftime("%Y-%m-%d"),
                            "domain_age_days": age_days,
                            "whois_status": "ok",
                            "whois_details": f"WHOIS server: {whois_server}"
                        }
            except Exception as e:
                result = {
                    "domain_age": "Unknown",
                    "domain_created_at": "",
                    "domain_age_days": "",
                    "whois_status": "error",
                    "whois_details": f"{type(e).__name__}: {e}"
                }

        WHOIS_CACHE.set(cache_key, result)
        return result


    def is_disposable_mx(self, mx_records: List[str]) -> bool:
        if not mx_records:
            return False
        for mx in mx_records:
            ml = mx.lower()
            if any(pat in ml for pat in self.DISPOSABLE_MX_PATTERNS):
                return True
        return False

    def is_trap_mx(self, mx_records: List[str]) -> bool:
        """Check if MX records match known spam trap infrastructure."""
        if not mx_records:
            return False
        for mx in mx_records:
            ml = mx.lower()
            if any(pat in ml for pat in self.TRAP_MX_PATTERNS):
                return True
        return False

    def detect_typo_domain(self, domain: str) -> Tuple[bool, str]:
        """Check if domain is within 1 edit of a canonical consumer mailbox domain.

        Returns (is_possible_typo, canonical_match).
        Uses MAGY 2025 as the reference list of real consumer domains.
        """
        domain = domain.lower()
        if domain in self.CANONICAL_CONSUMER_DOMAINS:
            return False, ""
        if domain in self.TYPO_EXEMPT_DOMAINS:
            return False, ""

        # Only compare against domains sharing the same TLD
        tld = domain.rsplit(".", 1)[-1] if "." in domain else ""
        candidates = self._canonical_by_tld.get(tld, [])
        for candidate in candidates:
            if abs(len(candidate) - len(domain)) > 1:
                continue
            if _is_one_edit_away(domain, candidate):
                return True, candidate

        return False, ""

    def is_role_account(self, email: str) -> bool:
        """Check if the local part of an email is a known role account."""
        if '@' not in email:
            return False
        local = email.split('@')[0].lower().strip()
        return local in self.ROLE_ACCOUNTS

    def is_disposamail_pattern(self, email: str) -> bool:
        """Check for disposamail-stuffed pattern per Spamhaus guidance.

        Pattern: exactly 10 chars, 5-7 letters then 3-5 numbers, domain usually .com
        e.g. johnson8274@gmail.com, michael927@yahoo.com, roberts1234@aol.com
        Returns True for strong match (.com domain), 'Weak' for non-.com domains.
        """
        if '@' not in email:
            return False
        parts = email.lower().strip().split('@')
        local = parts[0]
        domain = parts[1] if len(parts) > 1 else ''
        if len(local) != 10 or not self.DISPOSAMAIL_REGEX.match(local):
            return False
        # .com domains are high confidence per Spamhaus
        return True if domain.endswith('.com') else 'Weak'

    def parse_engagement_months(self, time_str: str) -> Optional[int]:
        """Parse 'X Years, Y Months' string into total months. Returns None if unparseable."""
        if not time_str or time_str.strip() in ('', 'Never Engaged', 'No Engagement'):
            return None
        import re as _re
        m = _re.match(r'(\d+)\s*Years?,\s*(\d+)\s*Months?', time_str.strip())
        if m:
            return int(m.group(1)) * 12 + int(m.group(2))
        return None

    def assess_email_flags(self, email: str, row: list, header: list,
                           engagement_col: int, opens_col: int, clicks_col: int,
                           domain_result: Optional[dict] = None) -> dict:
        """Generate email-level flags: role account, disposamail pattern, engagement risk."""
        disposamail_result = self.is_disposamail_pattern(email)
        # True = strong match (.com), 'Weak' = pattern match but non-.com domain
        flags = {
            "is_role_account": self.is_role_account(email),
            "is_disposamail_pattern": "Strong" if disposamail_result is True else ("Weak" if disposamail_result == 'Weak' else False),
            "engagement_risk": "",
            "email_risk_score": 0,
            "email_risk_level": "",
            "email_risk_factors": "",
        }

        # Engagement-based recycled trap risk
        if engagement_col >= 0 and header:
            time_str = row[engagement_col] if len(row) > engagement_col else ""
            opens = 0
            clicks = 0
            try:
                opens = int(row[opens_col]) if opens_col >= 0 and len(row) > opens_col else 0
            except (ValueError, TypeError):
                pass
            try:
                clicks = int(row[clicks_col]) if clicks_col >= 0 and len(row) > clicks_col else 0
            except (ValueError, TypeError):
                pass

            total_engagement = opens + clicks
            months = self.parse_engagement_months(time_str)

            if time_str.strip() == 'Never Engaged' and total_engagement == 0:
                flags["engagement_risk"] = "Never Engaged"
            elif months is not None and months >= 18 and total_engagement == 0:
                flags["engagement_risk"] = "Recycled Trap Risk (18+ months, no engagement)"
            elif months is not None and months >= 12 and total_engagement == 0:
                flags["engagement_risk"] = "Stale (12+ months, no engagement)"

        # Compound risk: disposamail pattern + no engagement = higher confidence
        if flags["is_disposamail_pattern"] in ("Strong", "Weak") and flags["engagement_risk"] in (
            "Never Engaged", "Recycled Trap Risk (18+ months, no engagement)"
        ):
            flags["engagement_risk"] += f" + Disposamail Pattern ({flags['is_disposamail_pattern']})"

        score = 0
        factors: List[str] = []

        def add(points: int, reason: str):
            nonlocal score
            score += points
            factors.append(reason)

        if domain_result:
            score += int(domain_result.get("risk_score", 0))
            if domain_result.get("risk_factors"):
                factors.extend(str(domain_result["risk_factors"]).split(" | "))
            if domain_result.get("catch_all_status") == "accept_all":
                add(10, "Mailbox is on a catch-all domain")

        if flags["is_role_account"]:
            add(10, "Role account")
        if flags["is_disposamail_pattern"] == "Strong":
            add(30, "Strong disposamail pattern")
        elif flags["is_disposamail_pattern"] == "Weak":
            add(15, "Weak disposamail pattern")

        engagement_risk = flags["engagement_risk"]
        if engagement_risk.startswith("Never Engaged"):
            add(25, "Never engaged")
        elif engagement_risk.startswith("Recycled Trap Risk"):
            add(35, "Recycled trap risk")
        elif engagement_risk.startswith("Stale"):
            add(15, "Stale engagement")

        score = min(score, 100)
        if score >= 85:
            level = "Critical"
        elif score >= 60:
            level = "High"
        elif score >= 30:
            level = "Medium"
        else:
            level = "Low"

        deduped_factors = list(dict.fromkeys(factors))
        flags["email_risk_score"] = score
        flags["email_risk_level"] = level
        flags["email_risk_factors"] = " | ".join(deduped_factors)
        return flags

    def is_parked_infrastructure(self, mx_records: List[str], ns_records: List[str]) -> Tuple[bool, str]:
        # Check MX records for explicit parking
        if mx_records and isinstance(mx_records, list):
            for mx in mx_records:
                ml = str(mx).lower()
                if any(pat in ml for pat in self.PARKED_MX_PATTERNS):
                    return True, f"Parked MX Server ({mx})"
                    
        # Check NS records for explicit parking
        if ns_records and isinstance(ns_records, list):
            for ns in ns_records:
                nl = str(ns).lower()
                if any(pat in nl for pat in self.PARKED_NS_PATTERNS):
                    return True, f"Parked Nameserver ({ns})"
                    
        return False, ""

    def root_for_website_check(self, domain: str) -> str:
        patterns = {
            r'^.*\.gmail\.com$': 'google.com',
            r'^.*\.googlemail\.com$': 'google.com',
            r'^.*\.google\.com$': 'google.com',
            r'^.*\.outlook\.com$': 'microsoft.com',
            r'^.*\.office365\.com$': 'microsoft.com',
            r'^.*\.hotmail\.com$': 'microsoft.com',
            r'^.*\.live\.com$': 'microsoft.com',
            r'^.*\.msn\.com$': 'microsoft.com',
            r'^.*\.yahoo\.com$': 'yahoo.com',
            r'^.*\.sbcglobal\.net$': 'yahoo.com',
        }
        for pat, root in patterns.items():
            if re.match(pat, domain, re.IGNORECASE):
                return root

        return self.get_organizational_domain(domain)

    async def _smtp_read_response(self, reader: asyncio.StreamReader) -> Tuple[int, str]:
        lines = []
        while True:
            line = await asyncio.wait_for(reader.readline(), timeout=SMTP_TIMEOUT)
            if not line:
                break
            decoded = line.decode("utf-8", errors="ignore").strip()
            lines.append(decoded)
            if len(decoded) < 4 or decoded[3] != "-":
                break

        if not lines:
            return 0, ""

        first = lines[0]
        try:
            code = int(first[:3])
        except ValueError:
            code = 0
        return code, " | ".join(lines)

    async def _smtp_send_command(self, writer: asyncio.StreamWriter, reader: asyncio.StreamReader, command: str) -> Tuple[int, str]:
        writer.write((command + "\r\n").encode("ascii", errors="ignore"))
        await asyncio.wait_for(writer.drain(), timeout=SMTP_TIMEOUT)
        return await self._smtp_read_response(reader)

    async def probe_catch_all(self, domain: str, mx_records: List[str]) -> dict:
        if not self.enable_catch_all:
            return {"status": "skipped", "details": "Catch-all probe disabled"}
        if not mx_records or mx_records == ["NULL-MX"]:
            return {"status": "skipped", "details": "No deliverable MX records"}

        probe_local = f"mxrayprobe-{uuid.uuid4().hex[:12]}"
        probe_recipient = f"{probe_local}@{domain}"
        candidates = mx_records[:2]

        async with self.smtp_semaphore:
            for mx_host in candidates:
                reader = None
                writer = None
                try:
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(mx_host, 25),
                        timeout=SMTP_TIMEOUT
                    )
                    code, banner = await self._smtp_read_response(reader)
                    if code < 200 or code >= 400:
                        raise RuntimeError(f"banner {code}: {banner}")

                    code, ehlo_resp = await self._smtp_send_command(writer, reader, f"EHLO {self.smtp_helo_name}")
                    if code >= 400 or code == 0:
                        code, ehlo_resp = await self._smtp_send_command(writer, reader, f"HELO {self.smtp_helo_name}")
                    if code >= 400 or code == 0:
                        last_error = f"{mx_host}: greeting rejected ({code})"
                        continue

                    code, mail_resp = await self._smtp_send_command(writer, reader, f"MAIL FROM:<{self.smtp_probe_from}>")
                    if code >= 500:
                        last_error = f"{mx_host}: MAIL FROM rejected ({code})"
                        continue

                    code, rcpt_resp = await self._smtp_send_command(writer, reader, f"RCPT TO:<{probe_recipient}>")
                    await self._smtp_send_command(writer, reader, "QUIT")

                    if 200 <= code < 300:
                        return {
                            "status": "accept_all",
                            "details": f"{mx_host}: accepted random recipient ({code})"
                        }
                    if 500 <= code < 600:
                        return {
                            "status": "rejects_random",
                            "details": f"{mx_host}: rejected random recipient ({code})"
                        }
                    if 400 <= code < 500:
                        return {
                            "status": "inconclusive",
                            "details": f"{mx_host}: temporary RCPT response ({code})"
                        }
                    return {
                        "status": "inconclusive",
                        "details": f"{mx_host}: unexpected RCPT response ({code}) {rcpt_resp}"
                    }
                except Exception as e:
                    last_error = f"{mx_host}: {type(e).__name__}: {e}"
                finally:
                    if writer is not None:
                        writer.close()
                        try:
                            await writer.wait_closed()
                        except Exception:
                            pass

        return {
            "status": "inconclusive",
            "details": last_error if 'last_error' in locals() else "No MX hosts could be probed"
        }

    def score_domain_risk(self, result: dict) -> Tuple[int, str, List[str]]:
        score = 0
        factors: List[str] = []

        def add(points: int, reason: str):
            nonlocal score
            score += points
            factors.append(reason)

        status = result.get("status", "")
        mx_category = result.get("mx_category", "")
        mx_provider = result.get("mx_provider", "")
        mx_family = result.get("mx_family", "")
        mx_risk_tier = result.get("mx_risk_tier", "")
        catch_all_status = result.get("catch_all_status", "")
        website_status = result.get("website_status", "")

        if status == "Trap":
            add(90, "Known trap MX infrastructure")
        if result.get("is_trap_mx"):
            add(10, "Trap MX match")
        if status == "Disposable":
            add(75, "Disposable mail infrastructure")
        if result.get("is_disposable_mx"):
            add(10, "Disposable MX match")
        if status == "Parked":
            add(70, "Parked domain")
        if status == "Invalid":
            add(60, "Invalid domain for mail")
        if status == "Suspicious":
            add(40, "Suspicious domain signals")
        if result.get("mx_rule_weight"):
            add(int(result["mx_rule_weight"]), f"MX provider rule: {mx_provider or mx_category}")

        if catch_all_status == "accept_all":
            add(35, "Accepts random recipients")
        elif catch_all_status == "inconclusive":
            add(5, "Catch-all probe inconclusive")

        if result.get("possible_typo_of"):
            add(20, f"Possible typo of {result['possible_typo_of']}")
        if not result.get("has_dmarc"):
            add(8, "No DMARC")
        if not result.get("has_spf"):
            add(5, "No SPF")
        if result.get("has_a") and not result.get("has_mx"):
            add(15, "A-only domain without MX")
        if website_status == "spam":
            add(20, "Spam or hacked website content")
        if mx_risk_tier == "elevated":
            add(10, f"Elevated-risk MX tier ({mx_provider or mx_family or 'custom'})")
        elif mx_risk_tier == "high":
            add(20, f"High-risk MX tier ({mx_provider or mx_family or 'custom'})")
        if mx_category == "Custom":
            add(5, "Unclassified MX provider")
        if result.get("domain_age") in ("Unknown", "Error"):
            add(3, "Domain age unavailable")
        age_days = result.get("domain_age_days")
        whois_status = result.get("whois_status", "")
        if isinstance(age_days, int):
            if age_days <= 30:
                add(35, "Very new domain (<=30 days)")
            elif age_days <= 90:
                add(25, "New domain (<=90 days)")
            elif age_days <= 365:
                add(12, "Young domain (<=1 year)")
        elif whois_status in ("error", "unparsed"):
            add(5, "WHOIS lookup inconclusive")
        if mx_category == "Custom" and not result.get("has_spf") and not result.get("has_dmarc"):
            add(18, "Custom MX with no SPF or DMARC")
        if mx_category == "Custom" and website_status in ("dead", "error", "unknown"):
            add(12, "Custom MX with weak or missing web presence")
        if catch_all_status == "accept_all" and mx_risk_tier in ("elevated", "high"):
            add(15, "Catch-all on elevated-risk MX infrastructure")
        if catch_all_status == "accept_all" and not result.get("has_dmarc"):
            add(8, "Catch-all without DMARC")
        if mx_family and any(tag in result.get("mx_signal_flags", "") for tag in ["forwarding", "routing", "alias"]):
            add(8, f"Forwarding-style MX family ({mx_family})")
        if result.get("override_status") == "known_bad":
            add(60, "Known-bad domain override")
        if result.get("override_status") == "allowlisted":
            add(-35, "Allowlisted domain override")
        risky_neighbor_ratio = result.get("cluster_risky_ratio", 0)
        cluster_size = int(result.get("cluster_size", 0) or 0)
        if cluster_size >= 3 and risky_neighbor_ratio >= 0.5:
            add(20, f"Risky MX cluster ({cluster_size} domains, {int(risky_neighbor_ratio * 100)}% risky)")
        elif cluster_size >= 3 and risky_neighbor_ratio >= 0.25:
            add(10, f"Elevated MX cluster ({cluster_size} domains, {int(risky_neighbor_ratio * 100)}% risky)")
        if result.get("cohort_typo_anomaly"):
            add(8, "Cohort typo anomaly")
        if result.get("cohort_risky_cluster_anomaly"):
            add(8, "Cohort risky-cluster anomaly")
        if result.get("historical_status_changed"):
            add(10, "Risk changed since previous run")
        if result.get("historical_seen_before") and result.get("historical_last_risk_level") in ("High", "Critical"):
            add(6, "Previously risky in history")

        score = max(0, min(score, 100))
        thresholds = self.rules.get("risk_band_thresholds", {})
        high_threshold = int(thresholds.get("high", 60))
        medium_threshold = int(thresholds.get("medium", 30))
        if score >= max(high_threshold + 25, 85):
            level = "Critical"
        elif score >= high_threshold:
            level = "High"
        elif score >= medium_threshold:
            level = "Medium"
        else:
            level = "Low"
        return score, level, list(dict.fromkeys(factors))

    def apply_domain_overrides(self, result: dict) -> None:
        domain = result.get("domain", "").lower()
        if domain in self.allowlisted_domains:
            result["override_status"] = "allowlisted"
            result["override_reason"] = "Matched domain_allowlist.csv"
            return
        if domain in self.known_bad_domains:
            result["override_status"] = "known_bad"
            result["override_reason"] = "Matched known-bad domain file"
            return
        result["override_status"] = ""
        result["override_reason"] = ""

    def apply_history_context(self, result: dict) -> None:
        previous = self.history_cache.get(result.get("domain", "").lower())
        if not previous:
            result["historical_seen_before"] = False
            result["historical_last_risk_level"] = ""
            result["historical_last_risk_score"] = ""
            result["historical_status_changed"] = False
            return
        last_level = str(previous.get("risk_level", ""))
        last_score = previous.get("risk_score", "")
        result["historical_seen_before"] = True
        result["historical_last_risk_level"] = last_level
        result["historical_last_risk_score"] = last_score
        result["historical_status_changed"] = (
            str(result.get("risk_level", "")) != last_level or
            str(result.get("status", "")) != str(previous.get("status", ""))
        )

    def enrich_cohort_signals(self, domain_results: Dict[str, dict]) -> dict:
        total_domains = len(domain_results)
        typo_count = sum(1 for r in domain_results.values() if r.get("possible_typo_of"))
        family_groups: Dict[str, List[dict]] = defaultdict(list)
        for result in domain_results.values():
            family = result.get("mx_family") or result.get("mx_provider") or ""
            if family:
                family_groups[family].append(result)

        risky_statuses = {"Trap", "Disposable", "Parked", "Suspicious", "Invalid"}
        risky_cluster_domain_count = 0
        for family, members in family_groups.items():
            risky_members = [r for r in members if r.get("status") in risky_statuses or int(r.get("risk_score", 0) or 0) >= 60]
            ratio = (len(risky_members) / len(members)) if members else 0.0
            for result in members:
                result["cluster_size"] = len(members)
                result["cluster_risky_domains"] = len(risky_members)
                result["cluster_risky_ratio"] = round(ratio, 4)
                result["cluster_family"] = family
                result["cluster_flag"] = "risky-cluster" if len(members) >= 3 and ratio >= 0.5 else ("mixed-cluster" if len(members) >= 3 and ratio >= 0.25 else "")
            if len(members) >= 3 and ratio >= 0.25:
                risky_cluster_domain_count += len(members)

        typo_ratio = (typo_count / total_domains) if total_domains else 0.0
        risky_cluster_ratio = (risky_cluster_domain_count / total_domains) if total_domains else 0.0
        cohort_rules = self.rules.get("cohort_anomaly", {})
        typo_threshold = float(cohort_rules.get("typo_ratio_threshold", 0.05))
        cluster_threshold = float(cohort_rules.get("risky_cluster_ratio_threshold", 0.08))
        min_rows = int(cohort_rules.get("min_rows", 50))
        typo_anomaly = total_domains >= min_rows and typo_ratio >= typo_threshold
        cluster_anomaly = total_domains >= min_rows and risky_cluster_ratio >= cluster_threshold

        for result in domain_results.values():
            result["cohort_total_domains"] = total_domains
            result["cohort_typo_ratio"] = round(typo_ratio, 4)
            result["cohort_risky_cluster_ratio"] = round(risky_cluster_ratio, 4)
            result["cohort_typo_anomaly"] = typo_anomaly
            result["cohort_risky_cluster_anomaly"] = cluster_anomaly

        return {
            "cohort_total_domains": total_domains,
            "cohort_typo_ratio": round(typo_ratio, 4),
            "cohort_risky_cluster_ratio": round(risky_cluster_ratio, 4),
            "cohort_typo_anomaly": typo_anomaly,
            "cohort_risky_cluster_anomaly": cluster_anomaly
        }

    def finalize_domain_results(self, domain_results: Dict[str, dict]) -> dict:
        for result in domain_results.values():
            self.apply_domain_overrides(result)
            self.apply_history_context(result)

        cohort_summary = self.enrich_cohort_signals(domain_results)

        for result in domain_results.values():
            risk_score, risk_level, risk_factors = self.score_domain_risk(result)
            result["risk_score"] = risk_score
            result["risk_level"] = risk_level
            result["risk_factors"] = " | ".join(risk_factors)
            self.apply_history_context(result)

        return cohort_summary

    def write_history(self, domain_results: Dict[str, dict]) -> None:
        ts = datetime.now().isoformat()
        try:
            with open(self.history_path, "a", encoding="utf-8") as f:
                for result in sorted(domain_results.values(), key=lambda r: r["domain"]):
                    record = {
                        "timestamp": ts,
                        "domain": result.get("domain"),
                        "status": result.get("status"),
                        "risk_score": result.get("risk_score"),
                        "risk_level": result.get("risk_level"),
                        "mx_family": result.get("mx_family"),
                        "mx_provider": result.get("mx_provider")
                    }
                    f.write(json.dumps(record, sort_keys=True) + "\n")
        except Exception as e:
            self.logger.warning(f"Failed writing history file: {e}")

    def write_review_outputs(self, domain_results: Dict[str, dict], review_output_csv: str, cluster_output_csv: str, cohort_output_json: str, cohort_summary: dict) -> None:
        review_fields = [
            "domain", "status", "reason", "risk_score", "risk_level",
            "mx_provider", "mx_family", "mx_risk_tier", "catch_all_status",
            "override_status", "cluster_size", "cluster_risky_ratio", "risk_factors"
        ]
        review_rows = []
        for result in domain_results.values():
            if result.get("risk_level") in ("High", "Critical") or result.get("override_status") in ("known_bad", "allowlisted") or result.get("cluster_flag"):
                review_rows.append({k: result.get(k, "") for k in review_fields})

        with open(review_output_csv, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=review_fields)
            writer.writeheader()
            for row in sorted(review_rows, key=lambda r: (-int(r.get("risk_score", 0) or 0), r.get("domain", ""))):
                writer.writerow(row)

        cluster_fields = [
            "cluster_family", "domains_in_cluster", "risky_domains", "risky_ratio",
            "providers", "risk_levels", "domains"
        ]
        clusters = defaultdict(list)
        for result in domain_results.values():
            family = result.get("cluster_family") or result.get("mx_family") or ""
            if family:
                clusters[family].append(result)

        with open(cluster_output_csv, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=cluster_fields)
            writer.writeheader()
            for family, members in sorted(clusters.items(), key=lambda item: (-len(item[1]), item[0])):
                risky_members = [m for m in members if m.get("risk_level") in ("High", "Critical") or m.get("status") in ("Trap", "Disposable", "Parked", "Suspicious", "Invalid")]
                writer.writerow({
                    "cluster_family": family,
                    "domains_in_cluster": len(members),
                    "risky_domains": len(risky_members),
                    "risky_ratio": round((len(risky_members) / len(members)) if members else 0.0, 4),
                    "providers": " | ".join(sorted({str(m.get("mx_provider", "")) for m in members if m.get("mx_provider")})),
                    "risk_levels": " | ".join(sorted({str(m.get("risk_level", "")) for m in members if m.get("risk_level")})),
                    "domains": " | ".join(sorted(m.get("domain", "") for m in members))
                })

        with open(cohort_output_json, "w", encoding="utf-8") as f:
            json.dump(cohort_summary, f, indent=2, sort_keys=True)

    def analyze_domain(self, dns_result: dict, web_result: dict, whois_result: dict) -> dict:
        domain = str(dns_result.get("domain", "unknown"))
        has_mx = bool(dns_result.get("has_mx", False))
        has_a = bool(dns_result.get("has_a", False))
        has_spf = bool(dns_result.get("has_spf", False))
        has_dmarc = bool(dns_result.get("has_dmarc", False))
        mx_category = str(dns_result.get("mx_category", "Unknown"))
        mx_provider = str(dns_result.get("mx_provider", mx_category))
        mx_family = str(dns_result.get("mx_family", ""))
        mx_risk_tier = str(dns_result.get("mx_risk_tier", ""))
        mx_signal_flags = str(dns_result.get("mx_signal_flags", ""))
        mx_rule_weight = int(dns_result.get("mx_rule_weight", 0) or 0)
        mx_records = dns_result.get("mx_records")
        ns_records = dns_result.get("ns_records")
        website_status = str(web_result.get("status", "unknown")) if web_result else "unknown"
        website_details = str(web_result.get("details", "")) if web_result else ""
        redirect_url = str(web_result.get("redirect_url", "")) if web_result else ""
        domain_age = str(whois_result.get("domain_age", "Unknown")) if whois_result else "Unknown"
        domain_created_at = str(whois_result.get("domain_created_at", "")) if whois_result else ""
        domain_age_days = whois_result.get("domain_age_days", "")
        whois_status = str(whois_result.get("whois_status", "skipped")) if whois_result else "skipped"
        whois_details = str(whois_result.get("whois_details", "")) if whois_result else ""

        mx_list = list(mx_records) if isinstance(mx_records, list) else []
        ns_list = list(ns_records) if isinstance(ns_records, list) else []

        # Detect null MX (RFC 7505: "MX 0 ." means domain rejects all mail)
        is_null_mx = mx_list == ["NULL-MX"]

        is_disposable = self.is_disposable_mx(mx_list)
        is_trap = self.is_trap_mx(mx_list)
        is_parked_infra, parked_reason = self.is_parked_infrastructure(mx_list, ns_list)
        is_possible_typo, typo_match = self.detect_typo_domain(domain)

        result = {
            "domain": domain,
            "has_mx": has_mx and not is_null_mx,
            "has_a": has_a,
            "has_spf": has_spf,
            "has_dmarc": has_dmarc,
            "mx_category": "Null MX" if is_null_mx else mx_category,
            "mx_provider": "Null MX" if is_null_mx else mx_provider,
            "mx_family": mx_family,
            "mx_risk_tier": "high" if is_null_mx else mx_risk_tier,
            "mx_signal_flags": mx_signal_flags,
            "mx_rule_weight": mx_rule_weight,
            "website_status": website_status,
            "website_details": website_details,
            "redirect_url": redirect_url,
            "catch_all_status": "skipped",
            "catch_all_details": "Catch-all probe not run",
            "is_disposable_mx": is_disposable,
            "is_trap_mx": is_trap,
            "possible_typo_of": typo_match,
            "domain_age": domain_age,
            "domain_created_at": domain_created_at,
            "domain_age_days": domain_age_days,
            "whois_status": whois_status,
            "whois_details": whois_details,
            "override_status": "",
            "override_reason": "",
            "cluster_family": mx_family,
            "cluster_size": 1,
            "cluster_risky_domains": 0,
            "cluster_risky_ratio": 0.0,
            "cluster_flag": "",
            "cohort_total_domains": 0,
            "cohort_typo_ratio": 0.0,
            "cohort_risky_cluster_ratio": 0.0,
            "cohort_typo_anomaly": False,
            "cohort_risky_cluster_anomaly": False,
            "historical_seen_before": False,
            "historical_last_risk_level": "",
            "historical_last_risk_score": "",
            "historical_status_changed": False,
            "risk_score": 0,
            "risk_level": "",
            "risk_factors": ""
        }

        if is_null_mx:
            result["status"] = "Invalid"
            result["reason"] = "Null MX (RFC 7505) - domain explicitly rejects all mail"
        elif is_parked_infra:
             result["status"] = "Parked"
             result["reason"] = parked_reason
        elif not has_mx and not has_a:
            if has_spf or has_dmarc:
                result["status"] = "Suspicious"
                result["reason"] = "SPF/DMARC present but no MX or A detected"
            else:
                result["status"] = "Invalid"
                result["reason"] = "No MX or A records - domain likely inactive"
        elif is_trap:
            result["status"] = "Trap"
            result["reason"] = "MX matches known spam trap infrastructure"
        elif is_disposable:
            result["status"] = "Disposable"
            result["reason"] = "Domain appears to use disposable email provider"
        elif website_status == "parked":
            result["status"] = "Parked"
            result["reason"] = "Website appears parked/for sale via HTTP"
        elif website_status == "spam":
            result["status"] = "Suspicious"
            result["reason"] = website_details if "Hacked" in website_details else "Website appears to be SEO spam / gambling"
        elif has_mx:
            result["status"] = "Valid"
            result["reason"] = "Domain has valid MX records"
        elif has_a:
            result["status"] = "Valid"
            result["reason"] = "Domain has valid A records (web-only domain)"
        elif website_status == "dead" or website_status == "error":
            result["status"] = "Suspicious"
            result["reason"] = "Website appears dead/unreachable/timeout"
        else:
            result["status"] = "Unknown"
            result["reason"] = "Unable to confidently classify domain"

        risk_score, risk_level, risk_factors = self.score_domain_risk(result)
        result["risk_score"] = risk_score
        result["risk_level"] = risk_level
        result["risk_factors"] = " | ".join(risk_factors)
        return result

    # ----------------- Pipeline orchestration -----------------

    async def process_domain_pipeline(self, domain: str) -> dict:
        """Process a single domain's full pipeline (DNS then HTTP if needed)"""
        
        # 1. DNS & WHOIS Phase
        try:
            dns_res, whois_result = await asyncio.gather(
                self.get_domain_dns(domain),
                self.check_whois(self.get_organizational_domain(domain))
            )
        except Exception as e:
            self.logger.error(f"DNS pipeline error for {domain}: {e}")
            dns_res = {
                "domain": domain, "mx_records": [], "mx_category": "Error", "mx_provider": "Error",
                "mx_family": "", "mx_risk_tier": "high", "mx_signal_flags": "dns-error", "mx_rule_weight": 10,
                "a_records": [], "ns_records": [], "spf_record": None, "dmarc_record": None,
                "has_mx": False, "has_a": False, "has_ns": False, "has_spf": False, "has_dmarc": False,
            }
            whois_result = {
                "domain_age": "Unknown",
                "domain_created_at": "",
                "domain_age_days": "",
                "whois_status": "error",
                "whois_details": "WHOIS skipped due to DNS pipeline error"
            }

        # Catch parking infrastructure early to avoid HTTP overhead
        mx_raw = dns_res.get("mx_records")
        ns_raw = dns_res.get("ns_records")
        
        mx_list = list(mx_raw) if isinstance(mx_raw, list) else []
        ns_list = list(ns_raw) if isinstance(ns_raw, list) else []

        is_parked_infra, _ = self.is_parked_infrastructure(mx_list, ns_list)
        
        # 2. HTTP Phase
        has_dns = dns_res.get("has_mx") or dns_res.get("has_a")
        web_res = {"status": "unknown", "details": "Check skipped"}
        catch_all_res = {"status": "skipped", "details": "Catch-all probe not applicable"}

        is_trusted_tld = any(domain.endswith(tld) for tld in ['.edu', '.gov', '.mil', '.int'])

        if self.check_website_enabled and has_dns and not is_parked_infra and not is_trusted_tld:
            root = self.get_organizational_domain(domain)
            try:
                web_res = await self.check_website(root)
            except Exception as e:
                 web_res = {"status": "error", "details": f"Check failed: {e}"}
        elif is_trusted_tld:
             web_res = {"status": "live", "details": "Skipped - Trusted TLD"}
        elif is_parked_infra:
             web_res = {"status": "parked", "details": "Skipped - Identified as parking via DNS infrastructure"}
        elif not has_dns:
             web_res = {"status": "dead", "details": "Skipped - No DNS records"}

        if self.enable_catch_all and dns_res.get("has_mx") and not is_parked_infra:
            try:
                catch_all_res = await self.probe_catch_all(domain, mx_list)
            except Exception as e:
                catch_all_res = {"status": "inconclusive", "details": f"Probe failed: {e}"}
        elif self.enable_catch_all and not dns_res.get("has_mx"):
            catch_all_res = {"status": "skipped", "details": "Catch-all probe requires MX records"}

        # 3. Finalize
        result = self.analyze_domain(dns_res, web_res, whois_result)
        result["catch_all_status"] = catch_all_res.get("status", "skipped")
        result["catch_all_details"] = catch_all_res.get("details", "")
        risk_score, risk_level, risk_factors = self.score_domain_risk(result)
        result["risk_score"] = risk_score
        result["risk_level"] = risk_level
        result["risk_factors"] = " | ".join(risk_factors)
        return result

    async def process_entries_async(self, input_file: str, file_type: str, email_column: int, output_csv: str, chunk_size: int = 50000, skip_rows: int = 0, email_column_name: str = ""):
        await self.setup()

        domain_output_csv = output_csv.replace('_analysis_', '_domain_analysis_')
        email_output_csv = output_csv.replace('_analysis_', '_email_analysis_')
        review_output_csv = output_csv.replace('_analysis_', '_review_queue_')
        cluster_output_csv = output_csv.replace('_analysis_', '_cluster_summary_')
        cohort_output_json = output_csv.replace('_analysis_', '_cohort_summary_').replace('.csv', '.json')

        fieldnames_domain = [
            "domain", "has_mx", "has_a", "has_spf", "has_dmarc",
            "mx_category", "mx_provider", "mx_family", "mx_risk_tier", "mx_signal_flags",
            "website_status", "website_details", "redirect_url",
            "catch_all_status", "catch_all_details",
            "is_disposable_mx", "is_trap_mx", "possible_typo_of", "domain_age",
            "domain_created_at", "domain_age_days", "whois_status", "whois_details",
            "override_status", "override_reason",
            "cluster_family", "cluster_size", "cluster_risky_domains", "cluster_risky_ratio", "cluster_flag",
            "cohort_total_domains", "cohort_typo_ratio", "cohort_risky_cluster_ratio",
            "cohort_typo_anomaly", "cohort_risky_cluster_anomaly",
            "historical_seen_before", "historical_last_risk_level", "historical_last_risk_score", "historical_status_changed",
            "status", "reason", "risk_score", "risk_level", "risk_factors"
        ]

        # Email-level flags (appended per-row in the email CSV only)
        fieldnames_email_flags = [
            "is_role_account", "is_disposamail_pattern", "engagement_risk",
            "email_risk_score", "email_risk_level", "email_risk_factors"
        ]

        # Engagement column indices (auto-detected from header)
        engagement_col = -1
        opens_col = -1
        clicks_col = -1

        print("\n" + "=" * 60)
        print(f"📊 Starting chunked analysis (Chunk size: {chunk_size} rows)")
        print(f"   🚀 Fully Async Pipeline Mode")
        print(f"   📁 Output file: {output_csv}")
        print("=" * 60)

        f_in = None
        try:
            if not os.path.exists(input_file):
                print(f"Error: File '{input_file}' not found.")
                return

            f_in = open(input_file, 'r', newline='', encoding='utf-8', errors='replace')

            reader = None
            header = []
            if file_type == 'csv':
                reader = csv.reader(f_in)
                header = next(reader, None)
                if header is not None:
                    header_map = {str(col).lower().strip(): i for i, col in enumerate(header)}
                    peek_row = None
                    if email_column_name:
                        lookup = email_column_name.lower().strip()
                        if lookup not in header_map:
                            raise ValueError(f"Column '{email_column_name}' not found in CSV header")
                        email_column = header_map[lookup]
                        print(f"📧 Using requested column: '{header[email_column]}' (index {email_column})")
                    elif email_column == 0 and header[0].lower().strip() != 'email':
                        peek_row = next(reader, None)
                        if peek_row:
                            reader = itertools.chain([peek_row], reader)
                        email_column, detected_name = self.detect_email_column(header, peek_row)
                        print(f"📧 Auto-detected analysis column: '{detected_name}' (index {email_column})")

                    # Auto-detect engagement columns from header
                    for name in ['time since last engagement', 'last engagement time', 'engagement time', 'time since engagement']:
                        if name in header_map:
                            engagement_col = header_map[name]
                            break
                    for name in ['opens', 'open count', 'total opens']:
                        if name in header_map:
                            opens_col = header_map[name]
                            break
                    for name in ['clicks', 'click count', 'total clicks']:
                        if name in header_map:
                            clicks_col = header_map[name]
                            break
                    if engagement_col >= 0:
                        print(f"📊 Auto-detected engagement column: '{header[engagement_col]}' (index {engagement_col})")
                    if opens_col >= 0 or clicks_col >= 0:
                        print(f"📊 Auto-detected opens/clicks columns: opens={opens_col}, clicks={clicks_col}")
            else:
                reader = f_in

            total_rows_processed = 0
            chunk_index = 1
            domain_results: Dict[str, dict] = {}
            
            if skip_rows > 0:
                print(f"⏩ Fast-forwarding and skipping the first {skip_rows} rows...")
                for _ in range(skip_rows):
                    try:
                        next(reader)
                        total_rows_processed += 1
                    except StopIteration:
                        break
            
            while True:
                chunk_rows = []
                try:
                    for _ in range(chunk_size):
                        row = next(reader)
                        chunk_rows.append(row)
                except StopIteration:
                    pass

                if not chunk_rows:
                    break

                total_rows_processed += len(chunk_rows)
                
                # Extract unique domains in this chunk
                chunk_domains = set()
                for row in chunk_rows:
                    if file_type == 'csv':
                        entry = row[email_column] if len(row) > email_column else ""
                    else:
                        entry = row.strip() if isinstance(row, str) else ""
                    
                    if entry:
                        d = self.extract_domain(entry)
                        if d:
                            chunk_domains.add(d)
                
                # Filter domains we need to process (not in cache)
                domains_to_process = [d for d in chunk_domains if DOMAIN_RESULT_CACHE.get(d) is None]
                
                if domains_to_process:
                    print(f"\r⏳ Chunk {chunk_index} | Rows: {total_rows_processed} | New Domains: {len(domains_to_process)}...", end='')
                    tasks = [asyncio.create_task(self.process_domain_pipeline(d)) for d in domains_to_process]
                    
                    completed_in_chunk = 0
                    total_in_chunk = len(tasks)
                    for coro in asyncio.as_completed(tasks):
                        res = await coro
                        DOMAIN_RESULT_CACHE.set(res["domain"], res)
                        domain_results[res["domain"]] = res
                        
                        completed_in_chunk += 1
                        if completed_in_chunk % 50 == 0 or completed_in_chunk == total_in_chunk:
                             print(f"\r⏳ Chunk {chunk_index} | Rows: {total_rows_processed} | Domains: {completed_in_chunk}/{total_in_chunk} ({(completed_in_chunk/total_in_chunk)*100:.1f}%)", end='')
                else:
                     print(f"\r⏳ Chunk {chunk_index} | Rows: {total_rows_processed} | All domains cached...", end='')
                    
                chunk_index += 1
                
                # Reset resolver periodically to prevent underlying pycares C-level file descriptor exhaust
                self.resolver = None
                await self.setup()

            # Pull cached results for domains that were already known before this run
            for key in list(DOMAIN_RESULT_CACHE.cache.keys()):
                value = DOMAIN_RESULT_CACHE.get(key)
                if isinstance(value, dict) and value.get("domain"):
                    domain_results[value["domain"]] = value

            cohort_summary = self.finalize_domain_results(domain_results)

            with open(domain_output_csv, 'w', newline='', encoding='utf-8') as f_domain:
                domain_writer = csv.DictWriter(f_domain, fieldnames=fieldnames_domain, extrasaction='ignore')
                domain_writer.writeheader()
                for domain in sorted(domain_results):
                    domain_writer.writerow(domain_results[domain])

            # Re-open input and write final email-level CSV with enriched domain signals
            with open(email_output_csv, 'w', newline='', encoding='utf-8') as f_email:
                email_writer = csv.writer(f_email)
                if file_type == 'csv':
                    email_writer.writerow((header or []) + fieldnames_domain + fieldnames_email_flags)
                    f_in_re = open(input_file, 'r', newline='', encoding='utf-8', errors='replace')
                    reader_re = csv.reader(f_in_re)
                    _ = next(reader_re, None)
                    if skip_rows > 0:
                        for _ in range(skip_rows):
                            try:
                                next(reader_re)
                            except StopIteration:
                                break
                else:
                    email_writer.writerow(["email"] + fieldnames_domain + fieldnames_email_flags)
                    f_in_re = open(input_file, 'r', newline='', encoding='utf-8', errors='replace')
                    reader_re = f_in_re
                    if skip_rows > 0:
                        for _ in range(skip_rows):
                            try:
                                next(reader_re)
                            except StopIteration:
                                break

                try:
                    for row in reader_re:
                        if file_type == 'csv':
                            entry = row[email_column] if len(row) > email_column else ""
                            out_row = list(row)
                        else:
                            entry = row.strip() if isinstance(row, str) else ""
                            out_row = [entry]

                        if entry:
                            d = self.extract_domain(entry)
                            res = domain_results.get(d) if d else None
                            if res:
                                out_row.extend([res.get(k, "") for k in fieldnames_domain])
                            else:
                                out_row.extend([""] * len(fieldnames_domain))

                            email_flags = self.assess_email_flags(
                                entry, row if file_type == 'csv' else [],
                                header if file_type == 'csv' else [],
                                engagement_col, opens_col, clicks_col,
                                res
                            )
                            out_row.extend([email_flags.get(k, "") for k in fieldnames_email_flags])
                        else:
                            out_row.extend([""] * len(fieldnames_domain))
                            out_row.extend([""] * len(fieldnames_email_flags))

                        email_writer.writerow(out_row)
                finally:
                    f_in_re.close()

            self.write_review_outputs(domain_results, review_output_csv, cluster_output_csv, cohort_output_json, cohort_summary)
            self.write_history(domain_results)

            print("\n")
            print("\n🎉 Analysis Complete!")
            print(f"   ✅ Total rows processed: {total_rows_processed}")
            print(f"   📄 Domain-level results saved to: {domain_output_csv}")
            print(f"   📄 Email-level results saved to:  {email_output_csv}")
            print(f"   📄 Review queue saved to:         {review_output_csv}")
            print(f"   📄 Cluster summary saved to:      {cluster_output_csv}")
            print(f"   📄 Cohort summary saved to:       {cohort_output_json}")
            print(f"   Cache stats: {self.cache_hits} hits, {self.cache_misses} misses")
        finally:
            if f_in:
                f_in.close()
            await self.cleanup()


# --------------------------------------------------------
# Main
# --------------------------------------------------------

def main():
    try:
        print("==== Email Domain Analyzer (high-performance) ====")
        print("MX / A / SPF / DMARC + scoring + optional website/catch-all checks")

        parser = argparse.ArgumentParser(
            description="Analyze email domains for deliverability and spam-trap risk."
        )
        parser.add_argument("input_file", help="Path to input file")
        parser.add_argument(
            "file_type",
            nargs="?",
            choices=["txt", "csv"],
            help="Input type. Defaults from file extension."
        )
        parser.add_argument(
            "skip_rows",
            nargs="?",
            type=int,
            default=0,
            help="Number of data rows to skip for resume runs"
        )
        parser.add_argument(
            "--catch-all",
            action="store_true",
            dest="enable_catch_all",
            help="Enable low-volume SMTP catch-all probing against MX hosts"
        )
        parser.add_argument(
            "--dns-only",
            action="store_true",
            help="Disable website checks and only use DNS and optional SMTP signals"
        )
        parser.add_argument(
            "--whois",
            action="store_true",
            help="Enable WHOIS / registry-age enrichment for organizational domains"
        )
        parser.add_argument(
            "--column",
            dest="email_column_name",
            help="CSV column name to analyze, e.g. recipient or recipientDomain"
        )
        args = parser.parse_args()

        input_file = args.input_file
        file_type = args.file_type if args.file_type else ('csv' if input_file.lower().endswith('.csv') else 'txt')
        skip_rows = args.skip_rows
        email_column = 0

        analyzer = EmailDomainAnalyzer(
            enable_catch_all=args.enable_catch_all,
            check_website=not args.dns_only,
            enable_whois=args.whois
        )

        output_csv = analyzer.generate_output_filename(input_file)
        if skip_rows > 0:
            output_csv = output_csv.replace('.csv', f'_resumed_{skip_rows}.csv')
            
        print(f"\nAnalysis will be written to: {output_csv}")
        print(f"Website checks: {'off' if args.dns_only else 'on'}")
        print(f"Catch-all probing: {'on' if args.enable_catch_all else 'off'}")
        print(f"WHOIS enrichment: {'on' if args.whois else 'off'}")

        start = time.time()
        
        # Python 3.8+ for asyncio fix on Windows, though script assumes Unix/generic mostly
        if sys.platform == 'win32':
             asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        
        asyncio.run(analyzer.process_entries_async(input_file, file_type, email_column, output_csv, skip_rows=skip_rows))
        
        elapsed = time.time() - start

        print(f"\nCompleted in {elapsed:.2f} seconds")
        print(f"Results saved to '{output_csv}'")

    except KeyboardInterrupt:
        print("\nInterrupted by user")
    except Exception as e:
        print(f"Error: {e}")
        logging.error(f"Application error: {e}", exc_info=True)


if __name__ == "__main__":
    main()
