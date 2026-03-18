#!/usr/bin/env python3
import asyncio
import csv
import sys
import re
import os
import time
import logging
from datetime import datetime
from typing import List, Dict, Optional
from collections import defaultdict
import json
import uuid

import dns.resolver
import aiosqlite
import aiohttp
from bs4 import BeautifulSoup

# --------------------------------------------------------
# Config & Logging
# --------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s: %(message)s',
    handlers=[
        logging.FileHandler('email_domain_analyzer.log'),
        logging.StreamHandler()
    ]
)

BATCH_SIZE = 500          # Domains per batch
QUERY_TIMEOUT = 5         # DNS lifetime per query (seconds)
MAX_CONCURRENT = 100      # Max concurrent HTTP/site checks
CONN_TIMEOUT = 3          # HTTP connection timeout
CHECK_WEBSITE = True      # Flip to False for DNS-only runs
DNS_CONCURRENCY = 50      # or even 20 if you want to be gentle

PROCESS_ID = str(uuid.uuid4())[:8]


def validate_config():
    if BATCH_SIZE <= 0:
        raise ValueError("BATCH_SIZE must be positive")
    if QUERY_TIMEOUT <= 0:
        raise ValueError("QUERY_TIMEOUT must be positive")
    if MAX_CONCURRENT <= 0:
        raise ValueError("MAX_CONCURRENT must be positive")
    if CONN_TIMEOUT <= 0:
        raise ValueError("CONN_TIMEOUT must be positive")
    logging.info("Configuration validation passed")


# --------------------------------------------------------
# Simple LRU Cache
# --------------------------------------------------------

class LRUCache:
    def __init__(self, capacity=10000):
        self.capacity = capacity
        self.cache = {}
        self.access_order = []

    def get(self, key):
        value = self.cache.get(key)
        if value is not None:
            if key in self.access_order:
                self.access_order.remove(key)
            self.access_order.append(key)
        return value

    def set(self, key, value):
        if key in self.cache:
            self.cache[key] = value
            if key in self.access_order:
                self.access_order.remove(key)
            self.access_order.append(key)
            return

        if len(self.cache) >= self.capacity:
            oldest = self.access_order.pop(0)
            del self.cache[oldest]

        self.cache[key] = value
        self.access_order.append(key)


DNS_CACHE = LRUCache(50000)
WEBSITE_CACHE = LRUCache(50000)


# --------------------------------------------------------
# Database Manager (SQLite / aiosqlite)
# --------------------------------------------------------

class DatabaseManager:
    def __init__(self, db_path='db/domain_cache.db'):
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self.db_path = db_path
        self.lock = asyncio.Lock()
        print(f"🔧 Using database: {self.db_path} (Process ID: {PROCESS_ID})")

    async def setup(self):
        """Initialize DB and tables, with safe PRAGMAs (no WAL)."""
        async with self.lock:
            async with aiosqlite.connect(self.db_path) as db:
                # Soft PRAGMAs; ignore if unsupported
                pragmas = [
                    "PRAGMA synchronous=NORMAL;",
                    "PRAGMA temp_store=MEMORY;",
                    "PRAGMA cache_size=-100000;"
                ]
                for p in pragmas:
                    try:
                        await db.execute(p)
                    except Exception as e:
                        logging.warning(f"PRAGMA failed ({p.strip()}): {e}")

                await db.execute("""
                    CREATE TABLE IF NOT EXISTS dns_cache (
                        domain TEXT PRIMARY KEY,
                        mx_records TEXT,
                        mx_category TEXT,
                        a_records TEXT,
                        spf_record TEXT,
                        dmarc_record TEXT,
                        has_mx INTEGER,
                        has_a INTEGER,
                        has_spf INTEGER,
                        has_dmarc INTEGER,
                        last_checked TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)

                await db.execute("""
                    CREATE TABLE IF NOT EXISTS website_checks (
                        domain TEXT PRIMARY KEY,
                        status TEXT,
                        details TEXT,
                        last_checked TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)

                await db.execute("""
                    CREATE TABLE IF NOT EXISTS meta (
                        key TEXT PRIMARY KEY,
                        value TEXT
                    )
                """)

                await db.commit()

    def get_connection(self):
        """Return an aiosqlite connection context manager."""
        return aiosqlite.connect(self.db_path)

    async def get_cached_domains(self, domains: List[str]) -> Dict[str, dict]:
        if not domains:
            return {}

        async with self.lock:
            async with aiosqlite.connect(self.db_path) as conn:
                q = f"SELECT * FROM dns_cache WHERE domain IN ({','.join('?' * len(domains))})"
                async with conn.execute(q, domains) as cur:
                    rows = await cur.fetchall()

        results = {}
        for row in rows:
            domain = row[0]
            results[domain] = {
                "domain": domain,
                "mx_records": row[1],
                "mx_category": row[2],
                "a_records": row[3],
                "spf_record": row[4],
                "dmarc_record": row[5],
                "has_mx": row[6],
                "has_a": row[7],
                "has_spf": row[8],
                "has_dmarc": row[9],
                "last_checked": row[10],
            }
        return results

    async def save_dns_result(self, result: dict):
        async with self.lock:
            async with aiosqlite.connect(self.db_path) as conn:
                await conn.execute("""
                    INSERT OR REPLACE INTO dns_cache (
                        domain, mx_records, mx_category, a_records,
                        spf_record, dmarc_record, has_mx, has_a,
                        has_spf, has_dmarc, last_checked
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                """, (
                    result.get("domain"),
                    json.dumps(result.get("mx_records", [])),
                    result.get("mx_category"),
                    json.dumps(result.get("a_records", [])),
                    result.get("spf_record"),
                    result.get("dmarc_record"),
                    int(result.get("has_mx", False)),
                    int(result.get("has_a", False)),
                    int(result.get("has_spf", False)),
                    int(result.get("has_dmarc", False)),
                ))
                await conn.commit()

    async def save_website_result(self, domain: str, status: str, details: str):
        async with self.lock:
            async with aiosqlite.connect(self.db_path) as conn:
                await conn.execute("""
                    INSERT OR REPLACE INTO website_checks (
                        domain, status, details, last_checked
                    ) VALUES (?, ?, ?, CURRENT_TIMESTAMP)
                """, (domain, status, details))
                await conn.commit()

    async def cleanup(self):
        pass


# --------------------------------------------------------
# Analyzer
# --------------------------------------------------------

class EmailDomainAnalyzer:

    def __init__(self):
        self.session: Optional[aiohttp.ClientSession] = None
        self.conn_timeout = aiohttp.ClientTimeout(total=CONN_TIMEOUT)
        self.semaphore = asyncio.Semaphore(MAX_CONCURRENT)
        self.check_website = CHECK_WEBSITE

        self.db = DatabaseManager()
        self.logger = logging.getLogger(__name__)

        self.retry_attempts = 3
        self.retry_delay = 1

        self.cache_hits = 0
        self.cache_misses = 0

        self.failed_website_cache = LRUCache(5000)

        self.DISPOSABLE_MX_PATTERNS = [
            "erinn.biz", "erinn-email.org",
            "mailinator.com", "10minutemail.com", "guerrillamail.com",
            "trashmail.com", "tempmail.com", "yopmail.com",
            "dispostable.com", "maildrop.cc", "getnada.com",
            "temp-mail.org", "emailondeck.com", "throwawaymail.com",
            "sharklasers.com", "grr.la", "mailcatch.com",
            "tempail.com", "moakt.com"
        ]

        self.parking_keywords = [
            "this domain is parked", "domain for sale", "buy this domain",
            "this domain may be for sale", "parkingcrew", "sedo", "afternic",
            "hugedomains", "this web page is parked", "future home of",
            "website coming soon", "under construction", "account suspended",
            "expired domain", "renew your domain"
        ]

    async def setup(self):
        if self.session is None:
            self.session = aiohttp.ClientSession(timeout=self.conn_timeout)
        await self.db.setup()

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

    def load_entries_from_file(self, input_file: str, file_type: str = 'txt', email_column: int = 0) -> List[str]:
        entries = []

        if not os.path.exists(input_file):
            print(f"Error: File '{input_file}' not found.")
            return entries

        if file_type == 'csv':
            with open(input_file, 'r', newline='', encoding='utf-8') as f:
                reader = csv.reader(f)
                for row in reader:
                    if len(row) > email_column:
                        entries.append(row[email_column].strip())
        else:
            with open(input_file, 'r', encoding='utf-8') as f:
                entries = [line.strip() for line in f if line.strip()]

        return entries

    def generate_output_filename(self, input_file: str) -> str:
        base, _ = os.path.splitext(input_file)
        ts = datetime.now().strftime('%Y%m%d_%H%M%S')
        return f"{base}_analysis_{ts}_{PROCESS_ID}.csv"

    # ----------------- DNS with dnspython -----------------

    async def check_mx_record(self, domain: str) -> List[str]:
        cache_key = f"mx:{domain}"
        cached = DNS_CACHE.get(cache_key)
        if cached is not None:
            self.cache_hits += 1
            return cached

        self.cache_misses += 1
        loop = asyncio.get_running_loop()

        def _resolve_mx():
            try:
                answers = dns.resolver.resolve(domain, 'MX', lifetime=QUERY_TIMEOUT)
                return sorted(str(r.exchange).rstrip('.') for r in answers)
            except (dns.resolver.NXDOMAIN,
                    dns.resolver.NoAnswer,
                    dns.resolver.NoNameservers,
                    dns.resolver.Timeout):
                return []
            except Exception as e:
                self.logger.debug(f"MX lookup failed for {domain}: {e}")
                return []

        mx_records = await loop.run_in_executor(None, _resolve_mx)
        DNS_CACHE.set(cache_key, mx_records)
        return mx_records

    async def check_a_record(self, domain: str) -> List[str]:
        cache_key = f"a:{domain}"
        cached = DNS_CACHE.get(cache_key)
        if cached is not None:
            self.cache_hits += 1
            return cached

        self.cache_misses += 1
        loop = asyncio.get_running_loop()

        def _resolve_a():
            try:
                answers = dns.resolver.resolve(domain, 'A', lifetime=QUERY_TIMEOUT)
                return sorted(str(r.address) for r in answers)
            except (dns.resolver.NXDOMAIN,
                    dns.resolver.NoAnswer,
                    dns.resolver.NoNameservers,
                    dns.resolver.Timeout):
                return []
            except Exception as e:
                self.logger.debug(f"A lookup failed for {domain}: {e}")
                return []

        a_records = await loop.run_in_executor(None, _resolve_a)
        DNS_CACHE.set(cache_key, a_records)
        return a_records

    async def check_txt_record(self, domain: str, record_type: str) -> Optional[str]:
        """
        TXT query for SPF/DMARC.
        For DMARC we pass '_dmarc.domain' in.
        """
        cache_key = f"txt:{record_type}:{domain}"
        cached = DNS_CACHE.get(cache_key)
        if cached is not None:
            self.cache_hits += 1
            return cached

        self.cache_misses += 1
        loop = asyncio.get_running_loop()

        def _resolve_txt():
            try:
                answers = dns.resolver.resolve(domain, 'TXT', lifetime=QUERY_TIMEOUT)
                for r in answers:
                    txt_record = ''.join(s.decode("utf-8") for s in r.strings)
                    if record_type == 'spf' and 'v=spf1' in txt_record:
                        return txt_record
                    if record_type == 'dmarc' and 'v=DMARC1' in txt_record:
                        return txt_record
                return None
            except (dns.resolver.NXDOMAIN,
                    dns.resolver.NoAnswer,
                    dns.resolver.NoNameservers,
                    dns.resolver.Timeout):
                return None
            except Exception as e:
                self.logger.debug(f"TXT lookup failed for {domain}: {e}")
                return None

        txt = await loop.run_in_executor(None, _resolve_txt)
        if txt is not None:
            DNS_CACHE.set(cache_key, txt)
        return txt

    def categorize_mx_provider(self, mx_records: List[str]) -> str:
        if not mx_records:
            return "No MX"

        providers = {
            'google': ['.google.com', '.googlemail.com', '.gmail.com'],
            'microsoft': ['.outlook.com', '.office365.com', '.hotmail.com', '.live.com', '.msn.com'],
            'yahoo': ['.yahoo.com', '.ymail.com', '.rocketmail.com'],
            'icloud': ['.icloud.com', '.me.com', '.mac.com'],
            'aol': ['.aol.com'],
            'zoho': ['.zoho.com', '.zohomail.com'],
            'protonmail': ['.protonmail.com'],
            'fastmail': ['.fastmail.com'],
            'yahoomx': ['.yahoodns.net'],
        }

        for mx in mx_records:
            mx_lower = mx.lower()
            for provider, patterns in providers.items():
                if any(mx_lower.endswith(pat) for pat in patterns):
                    return provider.capitalize()

        return "Custom"

    async def get_domain_records(self, domain: str) -> dict:
        domain = domain.strip().lower()

        mx_records = await self.check_mx_record(domain)
        a_records = await self.check_a_record(domain)
        spf_record = await self.check_txt_record(domain, 'spf')
        dmarc_record = await self.check_txt_record(f"_dmarc.{domain}", 'dmarc')

        mx_category = self.categorize_mx_provider(mx_records)
        has_mx = bool(mx_records)
        has_a = bool(a_records)
        has_spf = spf_record is not None
        has_dmarc = dmarc_record is not None

        result = {
            "domain": domain,
            "mx_records": mx_records,
            "mx_category": mx_category,
            "a_records": a_records,
            "spf_record": spf_record,
            "dmarc_record": dmarc_record,
            "has_mx": has_mx,
            "has_a": has_a,
            "has_spf": has_spf,
            "has_dmarc": has_dmarc
        }

        await self.db.save_dns_result(result)
        return result

    async def get_domain_records_with_retry(self, domain: str) -> dict:
        for attempt in range(self.retry_attempts):
            try:
                return await self.get_domain_records(domain)
            except Exception as e:
                if attempt == self.retry_attempts - 1:
                    self.logger.error(f"Failed to get records for {domain}: {e}")
                    return self._create_error_result(domain, str(e))
                await asyncio.sleep(self.retry_delay * (attempt + 1))

        return self._create_error_result(domain, "Max retries exceeded")

    # ----------------- Website cache + HTTP -----------------

    async def get_cached_website_result(self, domain: str) -> Optional[dict]:
        try:
            print(f"   🔍 Checking database cache for website: {domain}")
            async with self.db.get_connection() as conn:
                async with conn.execute(
                    "SELECT status, details FROM website_checks WHERE domain = ?",
                    (domain,)
                ) as cur:
                    row = await cur.fetchone()
                    if row:
                        print(f"   ✅ Using cached website result for {domain}")
                        return {"status": row[0], "details": row[1]}
        except Exception as e:
            print(f"   ⚠️  Error reading website cache: {e}")
        return None

    async def check_domain_liveness_async(self, domain: str) -> dict:
        domain = domain.strip().lower()

        cached = WEBSITE_CACHE.get(domain)
        if cached:
            self.cache_hits += 1
            return cached

        db_result = await self.get_cached_website_result(domain)
        if db_result:
            WEBSITE_CACHE.set(domain, db_result)
            self.cache_hits += 1
            return db_result

        self.cache_misses += 1

        failed = self.failed_website_cache.get(domain)
        if failed:
            print(f"   🔁 Skipping repeat failed website: {domain}")
            return failed

        async with self.semaphore:
            try:
                result = await self._check_single_domain_async(domain)
                await self.db.save_website_result(
                    domain,
                    result.get("status", "unknown"),
                    result.get("details", "")
                )
                WEBSITE_CACHE.set(domain, result)
                return result
            except Exception as e:
                err = {"status": "error", "details": f"Check failed: {e}"}
                WEBSITE_CACHE.set(domain, err)
                self.failed_website_cache.set(domain, err)
                return err

    async def _check_single_domain_async(self, domain: str) -> dict:
        try:
            async with self.session.get(f"http://{domain}", allow_redirects=True) as resp:
                text = await resp.text()
                soup = BeautifulSoup(text, 'html.parser')
                body_text = soup.get_text().lower() if soup else ""

                if any(k in body_text for k in self.parking_keywords):
                    result = {"status": "parked", "details": "Domain appears parked/for sale"}
                    self.failed_website_cache.set(domain, result)
                    return result

            return {"status": "live", "details": "Website is live"}
        except Exception as e:
            result = {"status": "dead", "details": str(e)}
            self.failed_website_cache.set(domain, result)
            return result

    # ----------------- Analysis -----------------

    def _create_error_result(self, domain: str, msg: str) -> dict:
        return {
            "domain": domain,
            "mx_records": [],
            "mx_category": "Error",
            "a_records": [],
            "spf_record": None,
            "dmarc_record": None,
            "has_mx": False,
            "has_a": False,
            "has_spf": False,
            "has_dmarc": False,
            "error": msg
        }

    def is_disposable_mx(self, mx_records: List[str]) -> bool:
        if not mx_records:
            return False
        for mx in mx_records:
            ml = mx.lower()
            if any(pat in ml for pat in self.DISPOSABLE_MX_PATTERNS):
                return True
        return False

    def _get_root_domain_for_website_check(self, domain: str) -> str:
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
        }
        for pat, root in patterns.items():
            if re.match(pat, domain, re.IGNORECASE):
                return root

        parts = domain.split('.')
        if len(parts) <= 2:
            return domain

        tlds = {
            'com', 'org', 'net', 'edu', 'gov', 'mil', 'int',
            'info', 'biz', 'io', 'ai', 'co', 'uk', 'de', 'fr', 'us', 'ca', 'au'
        }

        if parts[-1] in tlds and len(parts[-2]) == 2:
            return '.'.join(parts[-3:])
        return '.'.join(parts[-2:])

    def analyze_domain_validity(self, dns_result: dict, web_result: dict) -> dict:
        domain = dns_result.get("domain", "unknown")
        has_mx = dns_result.get("has_mx", False)
        has_a = dns_result.get("has_a", False)
        has_spf = dns_result.get("has_spf", False)
        has_dmarc = dns_result.get("has_dmarc", False)
        mx_category = dns_result.get("mx_category", "Unknown")
        mx_records = dns_result.get("mx_records", [])
        website_status = web_result.get("status", "unknown") if web_result else "unknown"
        website_details = web_result.get("details", "") if web_result else ""

        is_disposable = self.is_disposable_mx(mx_records)

        result = {
            "domain": domain,
            "has_mx": has_mx,
            "has_a": has_a,
            "has_spf": has_spf,
            "has_dmarc": has_dmarc,
            "mx_category": mx_category,
            "website_status": website_status,
            "website_details": website_details,
            "is_disposable_mx": is_disposable
        }

        if not has_mx and not has_a:
            result["status"] = "Invalid"
            result["reason"] = "No MX or A records - domain likely inactive or misconfigured"
        elif is_disposable:
            result["status"] = "Disposable"
            result["reason"] = "Domain appears to use disposable email provider"
        elif website_status == "parked":
            result["status"] = "Parked"
            result["reason"] = "Website appears parked/for sale"
        elif website_status == "dead":
            result["status"] = "Suspicious"
            result["reason"] = "Website appears dead/unreachable"
        elif has_mx:
            result["status"] = "Valid"
            result["reason"] = "Domain has valid MX records"
        elif has_a:
            result["status"] = "Valid"
            result["reason"] = "Domain has valid A records (web-only domain)"
        else:
            result["status"] = "Unknown"
            result["reason"] = "Unable to confidently classify domain"

        return result

    # ----------------- DB diagnostics -----------------

    async def show_database_cache_status(self):
        try:
            async with self.db.get_connection() as conn:
                async with conn.execute("SELECT COUNT(*) FROM dns_cache") as cur:
                    dns_count = (await cur.fetchone())[0]
                async with conn.execute("SELECT COUNT(*) FROM website_checks") as cur:
                    web_count = (await cur.fetchone())[0]

            print("📚 Database cache status:")
            print(f"   DNS cache entries: {dns_count}")
            print(f"   Website cache entries: {web_count}")
        except Exception as e:
            print(f"   ⚠️  Error reading cache status: {e}")

    # ----------------- Batch orchestration -----------------

    async def get_domain_records_batch(self, domains: List[str]) -> Dict[str, dict]:
        results: Dict[str, dict] = {}

        cached_results = await self.db.get_cached_domains(domains)
        domains_to_check = [d for d in domains if d not in cached_results]

        print("📊 Cache Statistics:")
        print(f"   Total domains: {len(domains)}")
        print(f"   Cached domains: {len(cached_results)}")
        print(f"   Domains needing live check: {len(domains_to_check)}")

        if domains_to_check:
            tasks = [self.get_domain_records_with_retry(d) for d in domains_to_check]
            live_results = await asyncio.gather(*tasks, return_exceptions=True)
            for d, res in zip(domains_to_check, live_results):
                if isinstance(res, Exception):
                    self.logger.error(f"Error checking {d}: {res}")
                    results[d] = self._create_error_result(d, str(res))
                else:
                    results[d] = res

        for d, db_res in cached_results.items():
            results[d] = {
                "domain": d,
                "mx_records": json.loads(db_res['mx_records']),
                "mx_category": db_res['mx_category'],
                "a_records": json.loads(db_res['a_records']),
                "spf_record": db_res['spf_record'],
                "dmarc_record": db_res['dmarc_record'],
                "has_mx": db_res['has_mx'],
                "has_a": db_res['has_a'],
                "has_spf": db_res['has_spf'],
                "has_dmarc": db_res['has_dmarc'],
            }

        return results

    async def process_entries_async(self, entries: List[str], output_csv: str):
        await self.setup()

        try:
            await self.show_database_cache_status()

            domain_groups = defaultdict(list)
            for entry in entries:
                domain = self.extract_domain(entry)
                if domain:
                    domain_groups[domain].append(entry)

            unique_domains = list(domain_groups.keys())
            total_domains = len(unique_domains)

            if total_domains == 0:
                print("No valid domains found for analysis.")
                return

            print("\n" + "=" * 60)
            print(f"📊 Starting analysis of {total_domains} unique domains")
            print(f"   📦 Batch size: {BATCH_SIZE}")
            print(f"   📁 Output file: {output_csv}")
            print("=" * 60)

            all_results: List[dict] = []

            for i in range(0, total_domains, BATCH_SIZE):
                batch = unique_domains[i:i + BATCH_SIZE]
                batch_num = i // BATCH_SIZE + 1
                total_batches = (total_domains + BATCH_SIZE - 1) // BATCH_SIZE

                print(f"\n📦 Processing Batch {batch_num}/{total_batches}")
                print(f"   Domains in this batch: {len(batch)}")
                print(f"   Overall progress: {i}/{total_domains} ({i / total_domains * 100:.1f}%)")
                print("-" * 40)

                batch_dns_results = await self.get_domain_records_batch(batch)

                website_results: Dict[str, dict] = {}
                if self.check_website:
                    root_to_domains = {}
                    for d in batch:
                        dns_res = batch_dns_results[d]
                        if dns_res.get("has_mx") or dns_res.get("has_a"):
                            root = self._get_root_domain_for_website_check(d)
                            root_to_domains.setdefault(root, set()).add(d)

                    if root_to_domains:
                        print(f"   🌐 Scheduling website checks for {len(root_to_domains)} root domains")
                        tasks = {
                            root: asyncio.create_task(self.check_domain_liveness_async(root))
                            for root in root_to_domains.keys()
                        }
                        for root, task in tasks.items():
                            try:
                                website_results[root] = await task
                            except Exception as e:
                                website_results[root] = {
                                    "status": "error",
                                    "details": f"Website check failed: {e}"
                                }
                    else:
                        print("   🌐 No DNS-positive domains in this batch; skipping website checks")

                batch_results: List[dict] = []
                for idx, d in enumerate(batch, 1):
                    global_idx = i + idx
                    overall_progress = global_idx / total_domains * 100

                    print(f"\n🔍 [{global_idx}/{total_domains}] Processing: {d}")
                    print(f"   Progress: {overall_progress:5.1f}% | Batch: {idx}/{len(batch)}")

                    dns_res = batch_dns_results[d]

                    mx_status = "✅" if dns_res.get("has_mx") else "❌"
                    a_status = "✅" if dns_res.get("has_a") else "❌"
                    spf_status = "✅" if dns_res.get("has_spf") else "❌"
                    dmarc_status = "✅" if dns_res.get("has_dmarc") else "❌"
                    print(
                        f"   DNS: MX{mx_status} A{a_status} SPF{spf_status} DMARC{dmarc_status} "
                        f"| Provider: {dns_res.get('mx_category', 'Unknown')}"
                    )

                    has_dns = dns_res.get("has_mx") or dns_res.get("has_a")

                    if self.check_website and has_dns:
                        root = self._get_root_domain_for_website_check(d)
                        if root != d:
                            print(f"   🌐 Website check: {root} (root of {d})")
                        else:
                            print(f"   🌐 Website check: {d}")

                        web_res = website_results.get(root, {
                            "status": "error",
                            "details": "Website check missing"
                        })

                        ws = web_res.get("status", "unknown")
                        if ws == "live":
                            print("   🌐 Website: ✅ Live")
                        elif ws == "parked":
                            print("   🌐 Website: 🚫 Parked")
                        elif ws == "dead":
                            print("   🌐 Website: ❌ Dead")
                        else:
                            print(f"   🌐 Website: ❓ {ws}")
                    else:
                        if not has_dns:
                            web_res = {"status": "dead", "details": "Skipped - No DNS records"}
                            print("   🌐 Website: ⏭️  Skipped (no DNS records)")
                        else:
                            web_res = {"status": "unknown", "details": "Website check disabled by configuration"}
                            print("   🌐 Website: ⏭️  Skipped (check_website=False)")

                    result = self.analyze_domain_validity(dns_res, web_res)
                    print(f"   ✅ Final status: {result.get('status', 'Unknown')}")
                    print(f"   📋 Reason: {result.get('reason', 'No reason provided')}")

                    batch_results.append(result)

                all_results.extend(batch_results)

                processed = i + len(batch)
                percent = processed / total_domains * 100
                print(f"\n📊 Batch {batch_num} Complete!")
                print(f"   Processed: {processed}/{total_domains} domains ({percent:.1f}%)")
                print(f"   Total results so far: {len(all_results)}")
                print("=" * 60)

            self.write_results_to_csv(all_results, output_csv)
            print("\n🎉 Analysis Complete!")
            print(f"   ✅ Total unique domains processed: {total_domains}")
            print(f"   📄 Results saved to: {output_csv}")

        except Exception as e:
            print(f"Error during processing: {e}")
            logging.error(f"Processing error: {e}")

    def write_results_to_csv(self, results: List[dict], output_csv: str):
        fieldnames = [
            "domain", "has_mx", "has_a", "has_spf", "has_dmarc",
            "mx_category", "website_status", "website_details",
            "is_disposable_mx", "status", "reason"
        ]
        with open(output_csv, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for r in results:
                writer.writerow(r)

        print(f"\nResults written to: {output_csv}")
        print(f"Cache stats: {self.cache_hits} hits, {self.cache_misses} misses")

    @staticmethod
    def merge_parallel_results(output_files: List[str], final_output_file: str):
        if not output_files:
            print("No output files provided for merging.")
            return

        print("\n📁 Merging parallel output files:")
        for f in output_files:
            print(f"   - {f}")

        latest_header = None
        headers_written = False

        with open(final_output_file, 'w', newline='', encoding='utf-8') as final_file:
            writer = csv.writer(final_file)

            for path in output_files:
                if not os.path.exists(path):
                    print(f"⚠️  Warning: File not found: {path}")
                    continue

                print(f"   📄 Reading: {path}")
                with open(path, 'r', encoding='utf-8') as inf:
                    reader = csv.reader(inf)
                    if headers_written:
                        next(reader, None)
                    else:
                        header = next(reader, None)
                        if header:
                            latest_header = header
                            writer.writerow(header)
                            headers_written = True

                    for row in reader:
                        writer.writerow(row)

        print(f"\n✅ Merge complete. Final results saved to: {final_output_file}")
        print(f"   Last header used: {latest_header}")


# --------------------------------------------------------
# Main
# --------------------------------------------------------

def main():
    analyzer = None
    try:
        print("==== Email Domain Analyzer ====")
        print("Combines MX lookup and domain / website validation")

        validate_config()

        if len(sys.argv) < 2:
            print("\nUsage:")
            print("  Basic:    python3 swissarmydomain2.py <input_file>")
            print("  Advanced: python3 swissarmydomain2.py <input_file> [file_type]")
            print("\nParameters:")
            print("  input_file   - Path to input file (required)")
            print("  file_type    - 'txt' or 'csv' (default: txt)")
            return

        input_file = sys.argv[1]
        file_type = sys.argv[2] if len(sys.argv) > 2 else 'txt'
        email_column = 0

        analyzer = EmailDomainAnalyzer()
        entries = analyzer.load_entries_from_file(input_file, file_type, email_column)
        if not entries:
            print("No entries found. Exiting.")
            return

        output_csv = analyzer.generate_output_filename(input_file)
        print(f"\nAnalysis will be written to: {output_csv}")

        start = time.time()
        asyncio.run(analyzer.process_entries_async(entries, output_csv))
        elapsed = time.time() - start

        print(f"\nCompleted in {elapsed:.2f} seconds")
        print(f"Results saved to '{output_csv}'")

    except KeyboardInterrupt:
        print("\nInterrupted by user")
    except Exception as e:
        print(f"Error: {e}")
        logging.error(f"Application error: {e}")
    finally:
        if analyzer:
            try:
                asyncio.run(analyzer.cleanup())
                asyncio.run(analyzer.db.cleanup())
            except RuntimeError:
                # If already in event loop (rare in CLI), ignore
                pass


if __name__ == "__main__":
    main()
