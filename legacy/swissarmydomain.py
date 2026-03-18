#!/usr/bin/env python3
import asyncio
import aiodns
import dns.resolver
import requests
import csv
import sys
import re
import os
import socket
import concurrent.futures
import time
import logging
from datetime import datetime
from typing import List, Dict, Optional, Any
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import aiohttp
from functools import lru_cache
from collections import defaultdict, OrderedDict
import sqlite3
from contextlib import asynccontextmanager
import aiosqlite  # For async SQLite
# Or for PostgreSQL:
# import asyncpg
import json
import uuid  # For generating unique process IDs

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('domain_analyzer.log'),
        logging.StreamHandler()
    ]
)

# Configuration
BATCH_SIZE = 200  # Up from 100
QUERY_TIMEOUT = 60  # Timeout for DNS queries in seconds
MAX_WORKERS = 10  # Default max workers for threading
MAX_CONCURRENT = 100  # Up from 50
CONN_TIMEOUT = 3  # Down from 5

# Generate unique process ID for parallel processing
PROCESS_ID = str(uuid.uuid4())[:8]  # Short unique ID for this process

def validate_config():
    """Validate configuration settings"""
    if BATCH_SIZE <= 0:
        raise ValueError("BATCH_SIZE must be positive")
    if QUERY_TIMEOUT <= 0:
        raise ValueError("QUERY_TIMEOUT must be positive")
    if MAX_WORKERS <= 0:
        raise ValueError("MAX_WORKERS must be positive")
    if MAX_CONCURRENT <= 0:
        raise ValueError("MAX_CONCURRENT must be positive")
    if CONN_TIMEOUT <= 0:
        raise ValueError("CONN_TIMEOUT must be positive")
    
    # Validate cache settings
    if DOMAIN_CACHE.maxsize <= 0:
        raise ValueError("DOMAIN_CACHE maxsize must be positive")
    if WEBSITE_CACHE.maxsize <= 0:
        raise ValueError("WEBSITE_CACHE maxsize must be positive")
    
    logging.info("Configuration validation passed")

class LRUCache:
    def __init__(self, maxsize=1000, ttl=3600):
        self.maxsize = maxsize
        self.ttl = ttl
        self.cache = OrderedDict()
        self.timestamps = {}
    
    def get(self, key):
        if key in self.cache:
            # Check if expired
            if time.time() - self.timestamps[key] > self.ttl:
                del self.cache[key]
                del self.timestamps[key]
                return None
            
            # Move to end (most recently used)
            self.cache.move_to_end(key)
            return self.cache[key]
        return None
    
    def set(self, key, value):
        if key in self.cache:
            self.cache.move_to_end(key)
        else:
            if len(self.cache) >= self.maxsize:
                # Remove oldest item
                oldest = next(iter(self.cache))
                del self.cache[oldest]
                del self.timestamps[oldest]
        
        self.cache[key] = value
        self.timestamps[key] = time.time()

# Initialize caches with proper management
DOMAIN_CACHE = LRUCache(maxsize=1000, ttl=86400)  # 24 hour TTL
WEBSITE_CACHE = LRUCache(maxsize=500, ttl=3600)   # 1 hour TTL

class DatabaseManager:
    def __init__(self, db_path=None):
        # Use process-specific database path for parallel processing
        if db_path is None:
            db_path = f".cache/domain_checks_{PROCESS_ID}.db"
        
        # Create cache directory if it doesn't exist
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self.db_path = db_path
        self.lock = asyncio.Lock()  # Add lock for database access
        self._pool = None  # Add connection pool
        
        print(f"🔧 Using database: {self.db_path} (Process ID: {PROCESS_ID})")
        
    async def setup(self):
        """Initialize database tables"""
        async with self.lock:
            async with aiosqlite.connect(self.db_path) as db:
                # Performance optimizations
                await db.execute('PRAGMA journal_mode=WAL')
                await db.execute('PRAGMA synchronous=NORMAL')
                await db.execute('PRAGMA cache_size=-2000000')  # 2GB cache
                await db.execute('PRAGMA temp_store=MEMORY')
                await db.execute('PRAGMA busy_timeout=5000')
                
                # Create tables for different types of checks
                await db.execute('''
                    CREATE TABLE IF NOT EXISTS domain_checks (
                        domain TEXT PRIMARY KEY,
                        mx_records TEXT,
                        mx_category TEXT,
                        a_records TEXT,
                        spf_record TEXT,
                        dmarc_record TEXT,
                        has_mx BOOLEAN,
                        has_a BOOLEAN,
                        has_spf BOOLEAN,
                        has_dmarc BOOLEAN,
                        last_checked TIMESTAMP,
                        CHECK_TTL INTEGER DEFAULT 86400
                    )
                ''')
                
                await db.execute('''
                    CREATE TABLE IF NOT EXISTS website_checks (
                        domain TEXT PRIMARY KEY,
                        status TEXT,
                        is_live BOOLEAN,
                        is_parked BOOLEAN,
                        details TEXT,
                        last_checked TIMESTAMP,
                        CHECK_TTL INTEGER DEFAULT 3600
                    )
                ''')
                
                await db.execute('''
                    CREATE TABLE IF NOT EXISTS results_history (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        domain TEXT,
                        original_input TEXT,
                        check_time TIMESTAMP,
                        status TEXT,
                        reason TEXT,
                        FOREIGN KEY (domain) REFERENCES domain_checks(domain)
                    )
                ''')
                
                # Add indexes for faster lookups
                await db.execute('CREATE INDEX IF NOT EXISTS idx_domain ON domain_checks(domain)')
                await db.execute('CREATE INDEX IF NOT EXISTS idx_last_checked ON domain_checks(last_checked)')
                
                await db.commit()
                
                # Create connection pool
                self._pool = await aiosqlite.connect(self.db_path)
                await self._pool.execute('PRAGMA journal_mode=WAL')
                await self._pool.execute('PRAGMA synchronous=NORMAL')
                await self._pool.execute('PRAGMA cache_size=-2000000')
                await self._pool.execute('PRAGMA temp_store=MEMORY')
                await self._pool.execute('PRAGMA busy_timeout=5000')

    async def cleanup(self):
        """Properly close database connections"""
        if self._pool:
            await self._pool.close()
            self._pool = None

    @asynccontextmanager
    async def get_connection(self):
        """Get database connection with context management and locking"""
        if not self._pool:
            raise RuntimeError("Database not initialized. Call setup() first.")
        
        async with self.lock:  # Use lock for all database operations
            try:
                yield self._pool
            except Exception as e:
                await self._pool.rollback()
                raise e

    async def get_cached_domains(self, domains):
        """Batch fetch multiple domains with TTL validation"""
        async with self.lock:
            async with aiosqlite.connect(self.db_path) as conn:
                conn.row_factory = aiosqlite.Row
                placeholders = ','.join('?' * len(domains))
                query = f"""
                    SELECT * FROM domain_checks 
                    WHERE domain IN ({placeholders})
                    AND datetime(last_checked, '+' || CHECK_TTL || ' seconds') > datetime('now')
                """
                async with conn.execute(query, domains) as cursor:
                    return {row['domain']: row for row in await cursor.fetchall()}

class EmailDomainAnalyzer:
    def __init__(self):
        # Increase connection pooling
        self.session = None
        self.conn_timeout = aiohttp.ClientTimeout(total=CONN_TIMEOUT)
        self.semaphore = asyncio.Semaphore(MAX_CONCURRENT)
        
        # Add connection pool for DNS
        self.resolver = aiodns.DNSResolver(nameservers=['8.8.8.8', '1.1.1.1'])
        
        # Batch DNS queries
        self.dns_queue = []
        self.dns_batch_size = 20
        
        # Add LRU cache for parking keywords
        self._parking_keywords_pattern = None
        
        # Add retry settings
        self.retry_attempts = 3
        self.retry_delay = 1.0
        
        # Add logger
        self.logger = logging.getLogger(__name__)
        
        # Common parking page indicators
        # Initialize cache statistics
        self.cache_hits = 0
        self.cache_misses = 0
        self.PARKING_KEYWORDS = [
            "domain is for sale", "buy this domain", 
            "domain parking", "parked domain", 
            "domain may be for sale", "domain auction",
            "this web page is parked", "this domain is parked", 
            "purchase this domain", "inquire about this domain",
            "domain broker", "domain for purchase",
            "coming soon", "register.com", "domain registration",
            "related searches", "whois lookup", "domain name",
            "this domain is available", "pending renewal or deletion",
            "under construction", "page is under construction", "coming soon",
            "networksolutions", "this page is under construction",
            "digi-searches", "why am i seeing this", "trademark free notice"
        ]
        
        # Add database manager
        self.db = DatabaseManager()
        self.db_lock = asyncio.Lock()  # Add lock for database operations
        
        # Add disposable/temporary email MX patterns
        self.DISPOSABLE_MX_PATTERNS = [
            # Erinn.biz patterns
            "recv1.erinn.biz", "recv2.erinn.biz", "recv3.erinn.biz",
            "recv4.erinn.biz", "recv6.erinn.biz", "recv7.erinn.biz",
            "recv8.erinn.biz", "recv100.erinn.biz", "recv101.erinn.biz",
            
            # Email fake services
            "email-fake.com", "emailfake.com", "generator.email",
            
            # Mail.tm and related
            "in.mail.tm",
            
            # Wabblywabble/Wallywatts
            "mail.wabblywabble.com", "mail.wallywatts.com",
            
            # Mailinator
            "mail.mailinator.com", "mail2.mailinator.com", "mailinator.com",
            
            # One-time mail services
            "mail.onetimemail.org", "h-email.net", "mail.haoo.com",
            
            # Various mail services
            "mx.mail-data.net",
            "mx1-hosting.jellyfish.systems",
            "mx2-hosting.jellyfish.systems",
            "mx3-hosting.jellyfish.systems",
            
            # Email box services
            "mx1.emaildbox.pro", "mx2.emaildbox.pro",
            "mx3.emaildbox.pro", "mx4.emaildbox.pro", "mx5.emaildbox.pro",
            
            # Forward email services
            "mx1.forwardemail.net", "mx2.forwardemail.net",
            
            # Private email services
            "mx1.privateemail.com", "mx2.privateemail.com",
            
            # Simple login
            "mx1.simplelogin.co", "mx2.simplelogin.co",
            
            # Other services
            "mx2.den.yt",
            "prd-smtp.10minutemail.com",
            "route1.mx.cloudflare.net",
            "route2.mx.cloudflare.net",
            "route3.mx.cloudflare.net",
            "tempm.com"
        ]

    @property
    def parking_keywords_pattern(self):
        """Cached compiled regex pattern for parking keywords"""
        if self._parking_keywords_pattern is None:
            pattern = '|'.join(map(re.escape, self.PARKING_KEYWORDS))
            self._parking_keywords_pattern = re.compile(pattern, re.IGNORECASE)
        return self._parking_keywords_pattern

    async def setup(self):
        """Initialize services"""
        await self.db.setup()
        if not self.session:
            connector = aiohttp.TCPConnector(
                limit=100,  # Total connection pool size
                limit_per_host=30,  # Connections per host
                ttl_dns_cache=300,  # DNS cache TTL
                use_dns_cache=True,
                keepalive_timeout=30
            )
            self.session = aiohttp.ClientSession(
                timeout=self.conn_timeout,
                connector=connector
            )

    async def cleanup(self):
        """Cleanup resources"""
        if self.session:
            await self.session.close()
            self.session = None

    def categorize_mx(self, mx_record):
        """Classifies the host based on MX record."""
        mx_lower = str(mx_record).lower()
        
        # Google services
        if any(provider in mx_lower for provider in ["google", "gmail", "googlemail", "aspmx", "alt1.aspmx", "alt2.aspmx", "alt3.aspmx", "alt4.aspmx", "gsuite"]):
            return "Google"
        
        # Microsoft services
        elif any(provider in mx_lower for provider in ["outlook", "hotmail", "office365", "microsoft", "protection.outlook", "mail.protection.outlook", "mx.protection.outlook", "msft", "exchange-online"]):
            return "Microsoft"
        
        # Yahoo services
        elif any(provider in mx_lower for provider in ["ymail", "yahoo", "yahoodns", "yahoodns.net"]):
            return "Yahoo"
        
        # Proofpoint
        elif any(provider in mx_lower for provider in ["pp-hosted", "ppe-hosted", "pphosted", "ppsmtp", "proofpoint"]):
            return "Proofpoint"
        
        # Mailgun
        elif "mailgun" in mx_lower:
            return "Mailgun"
        
        # Apple services
        elif any(provider in mx_lower for provider in ["icloud", "me.com", "mac.com", "apple"]):
            return "Apple"
        
        # Zoho
        elif "zoho" in mx_lower:
            return "Zoho"
        
        # Fastmail
        elif "fastmail" in mx_lower:
            return "Fastmail"
        
        # ProtonMail
        elif any(provider in mx_lower for provider in ["protonmail", "proton.me", "pm.me"]):
            return "ProtonMail"
        
        # GMX or Mail.com
        elif any(provider in mx_lower for provider in ["gmx", "mail.com"]):
            return "GMX"
        
        # Tencent QQ
        elif "qq.com" in mx_lower:
            return "Tencent QQ"
        
        # Naver
        elif "naver" in mx_lower:
            return "Naver"
        
        # NetEase
        elif any(provider in mx_lower for provider in ["163.com", "126.com", "netease"]):
            return "NetEase"
        
        # Yandex
        elif "yandex" in mx_lower:
            return "Yandex"
        
        # Mail.ru
        elif "mail.ru" in mx_lower:
            return "Mail.ru"
        
        # AOL
        elif "aol" in mx_lower:
            return "AOL"
        
        # IONOS (formerly 1&1)
        elif any(provider in mx_lower for provider in ["ionos", "1and1", "kundenserver"]):
            return "IONOS"
        
        # Rackspace
        elif "rackspace" in mx_lower:
            return "Rackspace"
        
        # Mimecast
        elif "mimecast" in mx_lower:
            return "Mimecast"
        
        # Barracuda
        elif "barracuda" in mx_lower:
            return "Barracuda"
        
        # SendGrid
        elif "sendgrid" in mx_lower:
            return "SendGrid"
        
        # GoDaddy / Secureserver
        elif any(provider in mx_lower for provider in ["godaddy", "secureserver.net", "emailsrvr.com", "secureserver"]):
            return "GoDaddy"
        
        # Namecheap / PrivateEmail
        elif any(provider in mx_lower for provider in ["privateemail", "namecheap"]):
            return "Namecheap"
        
        # OVH
        elif any(provider in mx_lower for provider in ["ovh", "mail.ovh.net"]):
            return "OVH"
        
        # Amazon SES
        elif any(provider in mx_lower for provider in ["amazonses", "aws", "ses"]):
            return "Amazon SES"
        
        # Cisco / IronPort
        elif any(provider in mx_lower for provider in ["cisco", "ironport"]):
            return "Cisco"
        
        # Mailchimp / Mandrill
        elif any(provider in mx_lower for provider in ["mailchimp", "mandrill"]):
            return "Mailchimp"
        
        # Zimbra
        elif "zimbra" in mx_lower:
            return "Zimbra"
        
        # cPanel
        elif "cpanel" in mx_lower:
            return "cPanel"
        
        # Hostgator
        elif "hostgator" in mx_lower:
            return "Hostgator"
        
        # Bluehost
        elif "bluehost" in mx_lower:
            return "Bluehost"
        
        # Sophos
        elif "sophos" in mx_lower:
            return "Sophos"
        
        # AWS WorkMail
        elif "workmail" in mx_lower:
            return "AWS WorkMail"
        
        # Other
        else:
            return "Other"

    def extract_domain(self, input_string):
        """Extracts and validates domain from input string, normalizing to root domain."""
        if not input_string or not isinstance(input_string, str):
            return None
        
        input_string = input_string.strip()
        
        # Handle email addresses
        if '@' in input_string:
            parts = input_string.split('@')
            if len(parts) != 2:
                print(f"Invalid email format: {input_string}")
                return None
            domain = parts[1].strip()
        else:
            domain = input_string
        
        # Validate domain format
        if not domain or '.' not in domain:
            print(f"Invalid domain format: {domain}")
            return None
        
        # Remove any trailing dots
        domain = domain.rstrip('.')
        
        # Basic domain validation regex
        domain_pattern = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$')
        
        if not domain_pattern.match(domain):
            print(f"Invalid domain characters: {domain}")
            return None
        
        domain = domain.lower()
        
        # Normalize to root domain for common email providers
        # This prevents false positives from subdomains
        email_provider_patterns = {
            # Google services
            r'^.*\.gmail\.com$': 'gmail.com',
            r'^.*\.googlemail\.com$': 'gmail.com',
            r'^.*\.google\.com$': 'google.com',
            
            # Microsoft services
            r'^.*\.outlook\.com$': 'outlook.com',
            r'^.*\.hotmail\.com$': 'hotmail.com',
            r'^.*\.live\.com$': 'live.com',
            r'^.*\.msn\.com$': 'msn.com',
            r'^.*\.microsoft\.com$': 'microsoft.com',
            
            # Yahoo services
            r'^.*\.yahoo\.com$': 'yahoo.com',
            r'^.*\.ymail\.com$': 'yahoo.com',
            r'^.*\.rocketmail\.com$': 'yahoo.com',
            r'^.*\.aol\.com$': 'aol.com',
            
            # Apple services
            r'^.*\.icloud\.com$': 'icloud.com',
            r'^.*\.me\.com$': 'me.com',
            r'^.*\.mac\.com$': 'mac.com',
            
            # Other major providers
            r'^.*\.protonmail\.com$': 'protonmail.com',
            r'^.*\.proton\.me$': 'proton.me',
            r'^.*\.pm\.me$': 'pm.me',
            r'^.*\.fastmail\.com$': 'fastmail.com',
            r'^.*\.zoho\.com$': 'zoho.com',
            r'^.*\.mail\.com$': 'mail.com',
            r'^.*\.gmx\.com$': 'gmx.com',
            r'^.*\.gmx\.de$': 'gmx.de',
            r'^.*\.gmx\.net$': 'gmx.net',
            r'^.*\.web\.de$': 'web.de',
            r'^.*\.t-online\.de$': 't-online.de',
            r'^.*\.qq\.com$': 'qq.com',
            r'^.*\.163\.com$': '163.com',
            r'^.*\.126\.com$': '126.com',
            r'^.*\.sina\.com$': 'sina.com',
            r'^.*\.sohu\.com$': 'sohu.com',
            r'^.*\.naver\.com$': 'naver.com',
            r'^.*\.daum\.net$': 'daum.net',
            r'^.*\.yandex\.ru$': 'yandex.ru',
            r'^.*\.mail\.ru$': 'mail.ru',
            r'^.*\.rambler\.ru$': 'rambler.ru',
        }
        
        # Check if domain matches any email provider pattern
        for pattern, root_domain in email_provider_patterns.items():
            if re.match(pattern, domain):
                return root_domain
        
        # For other domains, extract the root domain (last two parts)
        # This handles cases like subdomain.example.com -> example.com
        parts = domain.split('.')
        if len(parts) >= 2:
            # Handle special cases for country-specific domains
            if len(parts) >= 3 and len(parts[-1]) == 2 and len(parts[-2]) <= 3:
                # Likely a country-specific domain like .co.uk, .com.au, etc.
                return '.'.join(parts[-3:])
            else:
                # Standard domain - take last two parts
                return '.'.join(parts[-2:])
        
        return domain

    async def get_mx_records(self, domain):
        """Resolves MX records for a domain with proper error handling."""
        cached_result = DOMAIN_CACHE.get(domain)
        if cached_result:
            print(f"Using cached MX result for {domain}")
            self.cache_hits += 1
            return cached_result

        self.cache_misses += 1

        try:
            print(f"Resolving MX for {domain}")
            # Add timeout to prevent hanging on unresponsive domains
            mx_records = await asyncio.wait_for(self.resolver.query(domain, 'MX'), timeout=QUERY_TIMEOUT)
            mx_hostnames = [str(record.host) for record in mx_records]
            
            # Validate results
            if not mx_hostnames:
                raise ValueError("No MX records found")
            
            DOMAIN_CACHE.set(domain, mx_hostnames)
            print(f"Found MX records for {domain}: {mx_hostnames}")
            return mx_hostnames
            
        except asyncio.TimeoutError:
            error_message = f"DNS query timeout for {domain}"
            print(error_message)
            DOMAIN_CACHE.set(domain, [])
            return []
            
        except Exception as e:
            error_message = f"DNS error for {domain}: {str(e)}"
            print(error_message)
            DOMAIN_CACHE.set(domain, [])
            return []

    async def get_domain_records(self, domain):
        """Get DNS records with proper fallback order: database -> live check"""
        
        # 1. Check database first with TTL validation
        async with self.db_lock:
            async with self.db.get_connection() as conn:
                row = await conn.execute(
                    "SELECT * FROM domain_checks WHERE domain = ? AND datetime(last_checked, '+' || CHECK_TTL || ' seconds') > datetime('now')",
                    (domain,)
                )
                db_result = await row.fetchone()
                if db_result:
                    print(f"✅ Using cached database record for {domain} (checked: {db_result['last_checked']})")
                    return {
                        "domain": domain,
                        "mx_records": json.loads(db_result['mx_records']),
                        "mx_category": db_result['mx_category'],
                        "a_records": json.loads(db_result['a_records']),
                        "spf_record": db_result['spf_record'],
                        "dmarc_record": db_result['dmarc_record'],
                        "has_mx": db_result['has_mx'],
                        "has_a": db_result['has_a'],
                        "has_spf": db_result['has_spf'],
                        "has_dmarc": db_result['has_dmarc']
                    }

        # 2. If not in database or expired, perform live checks
        print(f"🔄 Performing live checks for {domain} (not in cache or expired)")
        
        result = {
            "domain": domain,
            "mx_records": [],
            "has_mx": False,
            "mx_category": "Unknown",
            "a_records": [],
            "has_a": False,
            "spf_record": None,
            "has_spf": False,
            "dmarc_record": None,
            "has_dmarc": False
        }
        
        # Get MX records
        try:
            mx_records = await self.get_mx_records(domain)
            if mx_records and not any("error" in str(r).lower() for r in mx_records):
                result["mx_records"] = mx_records
                result["has_mx"] = True
                mx_string = ", ".join(mx_records)
                result["mx_category"] = self.categorize_mx(mx_string)
        except Exception as e:
            print(f"Error getting MX records for {domain}: {e}")
        
        # Get A records
        try:
            a_records = await asyncio.get_event_loop().run_in_executor(
                None, lambda: dns.resolver.resolve(domain, 'A'))
            result["a_records"] = [str(record) for record in a_records]
            result["has_a"] = True
        except Exception:
            pass
        
        # Get SPF record
        try:
            txt_records = await asyncio.get_event_loop().run_in_executor(
                None, lambda: dns.resolver.resolve(domain, 'TXT'))
            for record in txt_records:
                record_text = record.to_text()
                if "v=spf1" in record_text:
                    result["spf_record"] = record_text
                    result["has_spf"] = True
                    break
        except Exception:
            pass
        
        # Get DMARC record
        try:
            dmarc_records = await asyncio.get_event_loop().run_in_executor(
                None, lambda: dns.resolver.resolve(f"_dmarc.{domain}", 'TXT'))
            for record in dmarc_records:
                record_text = record.to_text()
                if "v=DMARC1" in record_text:
                    result["dmarc_record"] = record_text
                    result["has_dmarc"] = True
                    break
        except Exception:
            pass
        
        # Store in database
        async with self.db_lock:
            async with self.db.get_connection() as conn:
                await conn.execute("""
                    INSERT OR REPLACE INTO domain_checks 
                    (domain, mx_records, mx_category, a_records, spf_record, 
                     dmarc_record, has_mx, has_a, has_spf, has_dmarc, last_checked)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
                """, (
                    domain,
                    json.dumps(result['mx_records']),
                    result['mx_category'],
                    json.dumps(result['a_records']),
                    result['spf_record'],
                    result['dmarc_record'],
                    result['has_mx'],
                    result['has_a'],
                    result['has_spf'],
                    result['has_dmarc']
                ))
                await conn.commit()
        
        # Store in memory cache
        DOMAIN_CACHE.set(domain, result)
        return result

    async def get_domain_records_with_retry(self, domain: str) -> dict:
        """Get domain records with retry logic."""
        for attempt in range(self.retry_attempts):
            try:
                return await self.get_domain_records(domain)
            except Exception as e:
                if attempt == self.retry_attempts - 1:
                    self.logger.error(f"Failed to get records for {domain} after {self.retry_attempts} attempts: {e}")
                    return self._create_error_result(domain, str(e))
                
                self.logger.warning(f"Attempt {attempt + 1} failed for {domain}, retrying...")
                await asyncio.sleep(self.retry_delay * (attempt + 1))
        
        return self._create_error_result(domain, "Max retries exceeded")

    def _create_error_result(self, domain: str, error_msg: str) -> dict:
        """Create a standardized error result."""
        return {
            "domain": domain,
            "mx_records": [],
            "has_mx": False,
            "mx_category": "Unknown",
            "a_records": [],
            "has_a": False,
            "spf_record": None,
            "has_spf": False,
            "dmarc_record": None,
            "has_dmarc": False,
            "error": error_msg
        }

    async def get_cached_website_result(self, domain):
        """Get cached website result from database"""
        try:
            print(f"   🔍 Checking database cache for website: {domain}")
            async with self.db.get_connection() as conn:
                query = """
                    SELECT * FROM website_checks 
                    WHERE domain = ? AND 
                    datetime(last_checked, '+' || CHECK_TTL || ' seconds') > datetime('now')
                """
                async with conn.execute(query, (domain,)) as cursor:
                    row = await cursor.fetchone()
                    if row:
                        print(f"   ✅ Using cached website result for {domain} (checked: {row['last_checked']})")
                        return {
                            "status": row['status'],
                            "details": row['details']
                        }
                    else:
                        print(f"   ❌ No cached website result found for {domain}")
                        # Let's also check if there's any record for this domain (even expired)
                        async with conn.execute("SELECT * FROM website_checks WHERE domain = ?", (domain,)) as cursor2:
                            expired_row = await cursor2.fetchone()
                            if expired_row:
                                print(f"   ⏰ Found expired website cache for {domain} (checked: {expired_row['last_checked']})")
                            else:
                                print(f"   📝 No website cache record found for {domain}")
        except Exception as e:
            print(f"   ❌ Error getting cached website result for {domain}: {e}")
        return None

    async def save_website_result(self, domain, status, details):
        """Save website result to database"""
        try:
            print(f"   💾 Saving website result to database: {domain} -> {status}")
            async with self.db.get_connection() as conn:
                await conn.execute("""
                    INSERT OR REPLACE INTO website_checks 
                    (domain, status, is_live, is_parked, details, last_checked)
                    VALUES (?, ?, ?, ?, ?, datetime('now'))
                """, (
                    domain,
                    status,
                    status == "live",
                    status == "parked",
                    details
                ))
                await conn.commit()
                print(f"   ✅ Successfully saved website result to database: {domain} -> {status}")
        except Exception as e:
            print(f"   ❌ Error saving website result for {domain}: {e}")

    async def check_domain_liveness_async(self, domain):
        """Asynchronous version of domain liveness check with database caching"""
        domain = domain.strip().lower()
        
        # 1. Check memory cache first (fastest)
        cached_result = WEBSITE_CACHE.get(domain)
        if cached_result:
            self.cache_hits += 1
            return cached_result
        
        # 2. Check database cache
        db_result = await self.get_cached_website_result(domain)
        if db_result:
            # Store in memory cache for future use
            WEBSITE_CACHE.set(domain, db_result)
            return db_result
        
        # 3. Perform live check
        self.cache_misses += 1
        print(f"🔄 Performing live website check for {domain}")
        
        async with self.semaphore:
            try:
                status = await self._check_single_domain_async(domain)
                
                # Save to database
                await self.save_website_result(domain, status.get("status", "unknown"), status.get("details", ""))
                
                # Store in memory cache
                WEBSITE_CACHE.set(domain, status)
                return status
            except Exception as e:
                error_status = {"status": "error", "details": f"Check failed: {str(e)}"}
                WEBSITE_CACHE.set(domain, error_status)
                return error_status

    def _get_root_domain_for_website_check(self, domain):
        """Get the root domain for website liveness checking."""
        # For website checking, we want to check the main website, not subdomains
        # This prevents false positives where subdomain.example.com is dead but example.com is live
        
        # Handle common email provider subdomains
        email_provider_patterns = {
            # Google services - check google.com for all subdomains
            r'^.*\.gmail\.com$': 'google.com',
            r'^.*\.googlemail\.com$': 'google.com',
            r'^.*\.google\.com$': 'google.com',
            
            # Microsoft services - check microsoft.com for all subdomains
            r'^.*\.outlook\.com$': 'microsoft.com',
            r'^.*\.hotmail\.com$': 'microsoft.com',
            r'^.*\.live\.com$': 'microsoft.com',
            r'^.*\.msn\.com$': 'microsoft.com',
            r'^.*\.microsoft\.com$': 'microsoft.com',
            
            # Yahoo services
            r'^.*\.yahoo\.com$': 'yahoo.com',
            r'^.*\.ymail\.com$': 'yahoo.com',
            r'^.*\.rocketmail\.com$': 'yahoo.com',
            r'^.*\.aol\.com$': 'aol.com',
            
            # Apple services
            r'^.*\.icloud\.com$': 'apple.com',
            r'^.*\.me\.com$': 'apple.com',
            r'^.*\.mac\.com$': 'apple.com',
            
            # Other major providers
            r'^.*\.protonmail\.com$': 'protonmail.com',
            r'^.*\.proton\.me$': 'proton.me',
            r'^.*\.pm\.me$': 'pm.me',
            r'^.*\.fastmail\.com$': 'fastmail.com',
            r'^.*\.zoho\.com$': 'zoho.com',
            r'^.*\.mail\.com$': 'mail.com',
            r'^.*\.gmx\.com$': 'gmx.com',
            r'^.*\.gmx\.de$': 'gmx.de',
            r'^.*\.gmx\.net$': 'gmx.net',
            r'^.*\.web\.de$': 'web.de',
            r'^.*\.t-online\.de$': 't-online.de',
            r'^.*\.qq\.com$': 'qq.com',
            r'^.*\.163\.com$': '163.com',
            r'^.*\.126\.com$': '126.com',
            r'^.*\.sina\.com$': 'sina.com',
            r'^.*\.sohu\.com$': 'sohu.com',
            r'^.*\.naver\.com$': 'naver.com',
            r'^.*\.daum\.net$': 'daum.net',
            r'^.*\.yandex\.ru$': 'yandex.ru',
            r'^.*\.mail\.ru$': 'mail.ru',
            r'^.*\.rambler\.ru$': 'rambler.ru',
        }
        
        # Check if domain matches any email provider pattern
        for pattern, root_domain in email_provider_patterns.items():
            if re.match(pattern, domain):
                return root_domain
        
        # For other domains, extract the root domain (last two parts)
        # This handles cases like subdomain.example.com -> example.com
        parts = domain.split('.')
        if len(parts) >= 2:
            # Handle special cases for country-specific domains
            if len(parts) >= 3 and len(parts[-1]) == 2 and len(parts[-2]) <= 3:
                # Likely a country-specific domain like .co.uk, .com.au, etc.
                return '.'.join(parts[-3:])
            else:
                # Standard domain - take last two parts
                return '.'.join(parts[-2:])
        
        return domain

    async def _check_single_domain_async(self, domain):
        """Asynchronous version of single domain check with proper timeout handling"""
        # Set shorter timeout for website checks to prevent hanging
        website_timeout = aiohttp.ClientTimeout(total=10, connect=5)  # 10s total, 5s connect
        
        # Try HTTPS first with timeout
        try:
            async with aiohttp.ClientSession(timeout=website_timeout) as session:
                async with session.get(f"https://{domain}", 
                                      allow_redirects=True,
                                      headers={'User-Agent': 'Mozilla/5.0'}) as response:
                    if response.status < 400:
                        is_parked, parking_reason = await self.check_if_parked_async(domain, response)
                        if is_parked:
                            return {"status": "parked", "details": parking_reason}
                        return {"status": "live", "details": f"HTTPS: {response.status}"}
        except asyncio.TimeoutError:
            print(f"   ⏰ HTTPS timeout for {domain}")
        except Exception as e:
            print(f"   ❌ HTTPS error for {domain}: {str(e)[:50]}...")
        
        # Try HTTP if HTTPS failed
        try:
            async with aiohttp.ClientSession(timeout=website_timeout) as session:
                async with session.get(f"http://{domain}", 
                                      allow_redirects=True,
                                      headers={'User-Agent': 'Mozilla/5.0'}) as response:
                    if response.status < 400:
                        is_parked, parking_reason = await self.check_if_parked_async(domain, response)
                        if is_parked:
                            return {"status": "parked", "details": parking_reason}
                        return {"status": "live", "details": f"HTTP: {response.status}"}
        except asyncio.TimeoutError:
            print(f"   ⏰ HTTP timeout for {domain}")
        except Exception as e:
            print(f"   ❌ HTTP error for {domain}: {str(e)[:50]}...")

        # Socket check as fallback with shorter timeout
        try:
            await asyncio.wait_for(
                asyncio.get_event_loop().run_in_executor(
                    None, lambda: socket.create_connection((domain, 80), timeout=3)
                ),
                timeout=5.0
            )
            return {"status": "live", "details": "Socket connection successful (port 80)"}
        except (asyncio.TimeoutError, socket.timeout):
            print(f"   ⏰ Socket timeout (port 80) for {domain}")
        except Exception as e:
            print(f"   ❌ Socket error (port 80) for {domain}: {str(e)[:50]}...")
        
        try:
            await asyncio.wait_for(
                asyncio.get_event_loop().run_in_executor(
                    None, lambda: socket.create_connection((domain, 443), timeout=3)
                ),
                timeout=5.0
            )
            return {"status": "live", "details": "Socket connection successful (port 443)"}
        except (asyncio.TimeoutError, socket.timeout):
            print(f"   ⏰ Socket timeout (port 443) for {domain}")
        except Exception as e:
            print(f"   ❌ Socket error (port 443) for {domain}: {str(e)[:50]}...")
        
        return {"status": "dead", "details": "Failed all connection attempts"}

    async def check_if_parked_async(self, domain, response):
        """Asynchronous version of parking check with timeout"""
        cache_key = f"parked_{domain}_{response.url}"
        
        cached_result = WEBSITE_CACHE.get(cache_key)
        if cached_result:
            self.cache_hits += 1
            return cached_result
        
        self.cache_misses += 1
        
        # Quick check for parking service URLs
        parking_services = set([
            "sedoparking.com", "hugedomains.com", "godaddyparking.com", 
            "parkingcrew.net", "parklogic.com", "fabulous.com/park"
        ])
        
        url_lower = str(response.url).lower()
        if any(service in url_lower for service in parking_services):
            result = (True, "Redirects to parking service")
            WEBSITE_CACHE.set(cache_key, result)
            return result

        try:
            # Add timeout for content reading
            content = await asyncio.wait_for(response.text(), timeout=5.0)
            soup = BeautifulSoup(content, 'html.parser')
            
            # Quick title check
            title = soup.title.text.lower() if soup.title else ""
            if self.parking_keywords_pattern.search(title):
                result = (True, "Parking keywords in title")
                WEBSITE_CACHE.set(cache_key, result)
                return result

            # Optimized body text check (limit to first 10KB to avoid slow processing)
            body_text = soup.get_text()[:10000].lower()
            matches = len(self.parking_keywords_pattern.findall(body_text))
            
            if matches >= 3:
                result = (True, f"Multiple parking keywords ({matches})")
                WEBSITE_CACHE.set(cache_key, result)
                return result

        except asyncio.TimeoutError:
            print(f"   ⏰ Content reading timeout for {domain}")
            result = (False, "Content reading timeout")
            WEBSITE_CACHE.set(cache_key, result)
            return result
        except Exception as e:
            print(f"   ❌ Content reading error for {domain}: {str(e)[:50]}...")
            result = (False, f"Error checking parking: {str(e)}")
            WEBSITE_CACHE.set(cache_key, result)
            return result

        result = (False, "Not parked")
        WEBSITE_CACHE.set(cache_key, result)
        return result

    def analyze_domain_validity(self, domain_records, liveness_info):
        """Analyze domain validity based on DNS records and liveness check."""
        domain = domain_records["domain"]
        
        # Initialize the result
        result = {
            "domain": domain,
            "original_input": domain,
            "mx_records": domain_records["mx_records"],
            "mx_category": domain_records["mx_category"],
            "a_records": domain_records["a_records"],
            "spf_record": domain_records["spf_record"],
            "dmarc_record": domain_records["dmarc_record"],
            "has_mx": domain_records["has_mx"],
            "has_a": domain_records["has_a"],
            "has_spf": domain_records["has_spf"],
            "has_dmarc": domain_records["has_dmarc"],
            "is_live": liveness_info["status"] == "live",
            "is_parked": liveness_info["status"] == "parked",
            "liveness_details": liveness_info["details"],
            "status": "Unknown",
            "reason": "",
            "is_disposable": False
        }
        
        # VERY specific parking MX patterns to avoid false positives
        PARKING_MX_PATTERNS = [
            "park-mx.above.com", 
            "sedoparking.com",
            "h-email.net",
            "parkingcrew.net",
            "bodis.com/parking",
            "fabulous.com/park"
        ]
        
        # Check for parking MX patterns
        mx_parking_detected = False
        for mx_record in result["mx_records"]:
            mx_host = str(mx_record).lower()
            for pattern in PARKING_MX_PATTERNS:
                if pattern in mx_host:
                    mx_parking_detected = True
                    result["parking_mx"] = mx_host
                    break
            if mx_parking_detected:
                break
                
        # Check for disposable email patterns
        for mx_record in result["mx_records"]:
            mx_host = str(mx_record).lower()
            if any(pattern.lower() in mx_host for pattern in self.DISPOSABLE_MX_PATTERNS):
                result["is_disposable"] = True
                result["status"] = "Invalid"
                result["reason"] = f"Disposable email provider detected: {mx_host}"
                return result

        # Decision logic
        if not result["has_mx"] and not result["has_a"]:
            result["status"] = "Invalid"
            result["reason"] = "No MX or A records found"
            return result
        
        if mx_parking_detected:
            result["is_parked"] = True
            result["status"] = "Invalid"
            result["reason"] = f"Domain uses parking MX: {result['parking_mx']}"
            return result
        
        if result["is_parked"]:
            result["status"] = "Invalid"
            result["reason"] = f"Parked domain: {result['liveness_details']}"
            return result
            
        if not result["is_live"]:
            # Site is not live
            if result["has_mx"]:
                # MX records exist but site is dead - Risky
                result["status"] = "Risky"
                result["reason"] = "Has MX records but site isn't live"
            else:
                # No MX and site is dead - Invalid
                result["status"] = "Invalid"
                result["reason"] = result["liveness_details"]
            return result
            
        # Domain is live and not parked - Valid
        result["status"] = "Valid"
        result["reason"] = "Domain passed all checks"
        return result

    async def process_entries_async(self, entries, output_csv):
        await self.setup()
        
        try:
            # Show current cache status
            await self.show_database_cache_status()
            
            # Group entries by domain
            domain_groups = defaultdict(list)
            for entry in entries:
                domain = self.extract_domain(entry)
                if domain:
                    domain_groups[domain].append(entry)
            
            unique_domains = list(domain_groups.keys())
            total_domains = len(unique_domains)
            all_results = []  # Track ALL results
            
            print(f"\n🚀 Starting Domain Analysis:")
            print(f"   📊 Total entries loaded: {len(entries)}")
            print(f"   🌐 Unique domains to check: {total_domains}")
            print(f"   📦 Batch size: {BATCH_SIZE}")
            print(f"   📁 Output file: {output_csv}")
            print(f"   ⏱️  Estimated time: {total_domains * 2:.0f} seconds ({total_domains * 2 / 60:.1f} minutes)")
            print(f"\n{'='*60}")
            
            # Process in batches
            for i in range(0, total_domains, BATCH_SIZE):
                batch = unique_domains[i:i + BATCH_SIZE]
                batch_results = []
                
                batch_num = i//BATCH_SIZE + 1
                total_batches = (total_domains + BATCH_SIZE - 1)//BATCH_SIZE
                
                print(f"\n📦 Processing Batch {batch_num}/{total_batches}")
                print(f"   Domains in this batch: {len(batch)}")
                print(f"   Overall progress: {i}/{total_domains} ({i/total_domains*100:.1f}%)")
                print(f"   {'-'*40}")
                
                # Use batch processing for better performance
                batch_dns_results = await self.get_domain_records_batch(batch)
                
                for idx, domain in enumerate(batch, 1):
                    global_idx = i + idx
                    overall_progress = global_idx / total_domains * 100
                    
                    print(f"\n🔍 [{global_idx:3d}/{total_domains}] Processing: {domain}")
                    print(f"   Progress: {overall_progress:5.1f}% | Batch: {idx}/{len(batch)}")
                    
                    # DNS checks (MX, A, SPF, DMARC) use the original domain/subdomain
                    dns_result = batch_dns_results[domain]
                    
                    # Show DNS results
                    mx_status = "✅" if dns_result.get("has_mx") else "❌"
                    a_status = "✅" if dns_result.get("has_a") else "❌"
                    spf_status = "✅" if dns_result.get("has_spf") else "❌"
                    dmarc_status = "✅" if dns_result.get("has_dmarc") else "❌"
                    
                    print(f"   DNS: MX{mx_status} A{a_status} SPF{spf_status} DMARC{dmarc_status} | Provider: {dns_result.get('mx_category', 'Unknown')}")
                    
                    # Only check website if domain has DNS records
                    if dns_result.get("has_mx") or dns_result.get("has_a"):
                        # For website liveness, check the root domain to avoid false positives
                        # But keep DNS checks on the original domain
                        root_domain = self._get_root_domain_for_website_check(domain)
                        if root_domain != domain:
                            print(f"   🌐 Website check: {root_domain} (root of {domain})")
                        else:
                            print(f"   🌐 Website check: {domain}")
                        
                        web_task = asyncio.create_task(self.check_domain_liveness_async(root_domain))
                        web_result = await web_task
                        
                        # Show website status
                        web_status = web_result.get("status", "unknown")
                        if web_status == "live":
                            print(f"   🌐 Website: ✅ Live")
                        elif web_status == "parked":
                            print(f"   🌐 Website: 🚫 Parked")
                        elif web_status == "dead":
                            print(f"   🌐 Website: ❌ Dead")
                        else:
                            print(f"   🌐 Website: ❓ {web_status}")
                    else:
                        # Skip website check if no DNS records
                        web_result = {"status": "dead", "details": "Skipped - No DNS records"}
                        print(f"   🌐 Website: ⏭️  Skipped (no DNS records)")
                    
                    result = self.analyze_domain_validity(dns_result, web_result)
                    
                    # Show final result
                    status = result.get("status", "Unknown")
                    if status == "Valid":
                        print(f"   📋 Result: ✅ Valid")
                    elif status == "Risky":
                        print(f"   📋 Result: ⚠️  Risky")
                    elif status == "Invalid":
                        print(f"   📋 Result: ❌ Invalid")
                    else:
                        print(f"   📋 Result: ❓ {status}")
                    
                    # Add results for each original input
                    for original_entry in domain_groups[domain]:
                        entry_result = result.copy()
                        entry_result["original_input"] = original_entry
                        batch_results.append(entry_result)
                
                # Add batch results to all results
                all_results.extend(batch_results)
                
                # Write progress
                self.write_results_to_csv(all_results, output_csv)
                
                # Update progress
                processed = i + len(batch)
                percent = (processed / total_domains) * 100
                print(f"\n📊 Batch {batch_num} Complete!")
                print(f"   Processed: {processed}/{total_domains} domains ({percent:.1f}%)")
                print(f"   Total results: {len(all_results)}")
                print(f"   {'='*60}")
            
            # Write final results
            self.write_results_to_csv(all_results, output_csv)
            print(f"\n🎉 Analysis Complete!")
            print(f"   ✅ Total domains processed: {total_domains}")
            print(f"   📄 Results saved to: {output_csv}")
            print(f"   📊 Total results: {len(all_results)}")
            print(f"   {'='*60}")
            
        except Exception as e:
            self.logger.error(f"Error during processing: {e}")
            raise
        finally:
            await self.cleanup()
            self.logger.info("Analysis complete")

    @staticmethod
    def write_results_to_csv(results, output_csv):
        """Separate method for CSV writing"""
        with open(output_csv, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow([
                'ENTRY', 'DOMAIN', 'STATUS', 'REASON', 'MX_AVAILABLE', 'MX_PROVIDER',
                'A_AVAILABLE', 'SPF_AVAILABLE', 'DMARC_AVAILABLE', 'SITE_LIVE', 'PARKED',
                'DISPOSABLE'
            ])
            
            for result in results:
                writer.writerow([
                    result.get("original_input", ""),
                    result.get("domain", ""),
                    result.get("status", ""),
                    result.get("reason", ""),
                    "Yes" if result.get("has_mx", False) else "No",
                    result.get("mx_category", "Unknown"),
                    "Yes" if result.get("has_a", False) else "No",
                    "Yes" if result.get("has_spf", False) else "No",
                    "Yes" if result.get("has_dmarc", False) else "No",
                    "Yes" if result.get("is_live", False) else "No",
                    "Yes" if result.get("is_parked", False) else "No",
                    "Yes" if result.get("is_disposable", False) else "No"
                ])

    def load_entries_from_file(self, file_path, file_type='txt', email_column=0):
        """Load entries from a file."""
        entries = []
        
        try:
            print(f"\n📂 Loading entries from: {file_path}")
            print(f"   File type: {file_type.upper()}")
            
            if file_type.lower() == 'csv':
                with open(file_path, 'r', encoding='utf-8') as csvfile:
                    reader = csv.reader(csvfile)
                    next(reader, None)  # Skip header row if it exists
                    for row_num, row in enumerate(reader, 1):
                        try:
                            entry = row[email_column].strip()
                            if entry:
                                entries.append(entry)
                                if row_num % 100 == 0:  # Show progress every 100 entries
                                    print(f"   Loaded {row_num} entries...")
                            else:
                                print(f"   Skipping empty entry in row {row_num}")
                        except IndexError:
                            print(f"   Skipping invalid row {row_num}: {row}")
            elif file_type.lower() == 'txt':
                with open(file_path, 'r', encoding='utf-8') as f:
                    for line_num, line in enumerate(f, 1):
                        entry = line.strip()
                        if entry:
                            entries.append(entry)
                            if line_num % 100 == 0:  # Show progress every 100 entries
                                print(f"   Loaded {line_num} entries...")
                        else:
                            print(f"   Skipping empty line {line_num}")
            else:
                print(f"❌ Error: Invalid file_type: '{file_type}'. Use 'csv' or 'txt'.")
                return []
                
            print(f"✅ Successfully loaded {len(entries)} entries from {file_path}")
            return entries
            
        except FileNotFoundError:
            print(f"❌ Error: Input file '{file_path}' not found.")
            return []
            
        except Exception as e:
            print(f"❌ Error loading entries: {e}")
            return []

    def print_cache_stats(self):
        """Print statistics about cache usage."""
        dns_cache_size = len(DOMAIN_CACHE.cache)
        website_cache_size = len(WEBSITE_CACHE.cache)
        total_cache_entries = dns_cache_size + website_cache_size
        
        print(f"\nCache Statistics:")
        print(f"  DNS Cache: {dns_cache_size} entries")
        print(f"  Website Cache: {website_cache_size} entries")
        print(f"  Total Cache: {total_cache_entries} entries")
        print(f"  Approximate memory saved from caching: {(dns_cache_size + website_cache_size) * 2}KB")
        
        # Calculate cache hit rate if possible
        if hasattr(self, 'cache_hits') and hasattr(self, 'cache_misses'):
            total_lookups = self.cache_hits + self.cache_misses
            hit_rate = (self.cache_hits / total_lookups * 100) if total_lookups > 0 else 0
            print(f"  Cache hit rate: {hit_rate:.2f}%")

    async def show_database_cache_status(self):
        """Show current database cache status"""
        try:
            async with self.db.get_connection() as conn:
                # Get total cached domains
                async with conn.execute("SELECT COUNT(*) as count FROM domain_checks") as cursor:
                    total_count = (await cursor.fetchone())[0]
                
                # Get non-expired cached domains
                async with conn.execute("""
                    SELECT COUNT(*) as count FROM domain_checks 
                    WHERE datetime(last_checked, '+' || CHECK_TTL || ' seconds') > datetime('now')
                """) as cursor:
                    valid_count = (await cursor.fetchone())[0]
                
                # Get recent domains (last 24 hours)
                async with conn.execute("""
                    SELECT domain, last_checked FROM domain_checks 
                    WHERE datetime(last_checked, '+' || CHECK_TTL || ' seconds') > datetime('now')
                    ORDER BY last_checked DESC LIMIT 10
                """) as cursor:
                    recent_domains = await cursor.fetchall()
                
                print(f"\n📊 Database Cache Status:")
                print(f"   Total cached domains: {total_count}")
                print(f"   Valid (non-expired) domains: {valid_count}")
                print(f"   Expired domains: {total_count - valid_count}")
                
                if recent_domains:
                    print(f"\n   Recent cached domains:")
                    for domain, last_checked in recent_domains:
                        print(f"     {domain} (checked: {last_checked})")
                
        except Exception as e:
            print(f"Error checking database cache: {e}")

    def generate_output_filename(self, input_file):
        """Generate output filename based on input file and timestamp with process ID for parallel processing."""
        input_basename = os.path.basename(input_file)
        input_name = os.path.splitext(input_basename)[0]
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        return f"{input_name}_analysis_{timestamp}_{PROCESS_ID}.csv"

    async def get_cached_results(self, domain):
        """Get complete cached results without rechecking"""
        async with self.db.get_connection() as conn:
            # Get DNS records
            dns_query = """
                SELECT * FROM domain_checks 
                WHERE domain = ? AND 
                datetime(last_checked, '+' || CHECK_TTL || ' seconds') > datetime('now')
            """
            async with conn.execute(dns_query, (domain,)) as cursor:
                dns_row = await cursor.fetchone()
                if not dns_row:
                    return None

            # Get website status
            web_query = """
                SELECT * FROM website_checks 
                WHERE domain = ? AND 
                datetime(last_checked, '+' || CHECK_TTL || ' seconds') > datetime('now')
            """
            async with conn.execute(web_query, (domain,)) as cursor:
                web_row = await cursor.fetchone()

            return {
                "domain": domain,
                "mx_records": json.loads(dns_row['mx_records']),
                "mx_category": dns_row['mx_category'],
                "a_records": json.loads(dns_row['a_records']),
                "spf_record": dns_row['spf_record'],
                "dmarc_record": dns_row['dmarc_record'],
                "has_mx": dns_row['has_mx'],
                "has_a": dns_row['has_a'],
                "has_spf": dns_row['has_spf'],
                "has_dmarc": dns_row['has_dmarc'],
                "is_live": web_row['is_live'] if web_row else False,
                "is_parked": web_row['is_parked'] if web_row else False,
                "status": "Valid",  # Will be updated by analyze_domain_validity
                "reason": ""
            }

    async def get_domain_records_batch(self, domains: List[str]) -> Dict[str, dict]:
        """Get domain records for multiple domains in batch"""
        results = {}
        
        # Check database first for all domains
        cached_results = await self.db.get_cached_domains(domains)
        
        # Process domains that need live checking
        domains_to_check = [d for d in domains if d not in cached_results]
        
        print(f"📊 Cache Statistics:")
        print(f"   Total domains: {len(domains)}")
        print(f"   Cached domains: {len(cached_results)}")
        print(f"   Domains needing live check: {len(domains_to_check)}")
        
        if domains_to_check:
            self.logger.info(f"Checking {len(domains_to_check)} domains live")
            
            # Create tasks for all domains that need checking
            tasks = [self.get_domain_records_with_retry(domain) for domain in domains_to_check]
            
            # Execute all tasks concurrently
            live_results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Process results
            for domain, result in zip(domains_to_check, live_results):
                if isinstance(result, Exception):
                    self.logger.error(f"Error checking {domain}: {result}")
                    results[domain] = self._create_error_result(domain, str(result))
                else:
                    results[domain] = result
        
        # Add cached results
        for domain, db_result in cached_results.items():
            results[domain] = {
                "domain": domain,
                "mx_records": json.loads(db_result['mx_records']),
                "mx_category": db_result['mx_category'],
                "a_records": json.loads(db_result['a_records']),
                "spf_record": db_result['spf_record'],
                "dmarc_record": db_result['dmarc_record'],
                "has_mx": db_result['has_mx'],
                "has_a": db_result['has_a'],
                "has_spf": db_result['has_spf'],
                "has_dmarc": db_result['has_dmarc']
            }
        
        return results

    @staticmethod
    def merge_parallel_results(output_files, final_output_file):
        """Merge results from multiple parallel processes into a single file."""
        print(f"\n🔗 Merging {len(output_files)} result files into: {final_output_file}")
        
        all_results = []
        headers_written = False
        
        with open(final_output_file, 'w', newline='', encoding='utf-8') as final_file:
            writer = csv.writer(final_file)
            
            for file_path in output_files:
                if not os.path.exists(file_path):
                    print(f"⚠️  Warning: File not found: {file_path}")
                    continue
                    
                print(f"   📄 Reading: {file_path}")
                with open(file_path, 'r', encoding='utf-8') as input_file:
                    reader = csv.reader(input_file)
                    
                    # Skip header for all files except the first
                    if headers_written:
                        next(reader, None)  # Skip header
                    else:
                        headers = next(reader)
                        writer.writerow(headers)
                        headers_written = True
                    
                    # Copy all data rows
                    for row in reader:
                        writer.writerow(row)
                        all_results.append(row)
        
        print(f"✅ Successfully merged {len(all_results)} results into: {final_output_file}")
        return len(all_results)

def merge_parallel_outputs(output_files, final_output_file):
    """Standalone function to merge parallel output files."""
    return EmailDomainAnalyzer.merge_parallel_results(output_files, final_output_file)

async def main():
    """Main function to set up and run the email domain analysis process."""
    analyzer = None
    
    try:
        print("==== Email Domain Analyzer ====")
        print("Combines MX lookup and domain validation into one tool")
        
        # Validate configuration
        validate_config()
        
        # Parse command-line arguments
        if len(sys.argv) < 2:
            print("\nUsage:")
            print("  Basic:    python email-domain-swissarmyknife.py <input_file>")
            print("  Advanced: python email-domain-swissarmyknife.py <input_file> [file_type]")
            print("\nParameters:")
            print("  input_file   - Path to input file (required)")
            print("  file_type    - Type of input file: 'txt' or 'csv' (default: txt)")
            print("  Note: For CSV files, column 1 is always used for emails/domains")
            return

        # Get input file
        input_file = sys.argv[1]
        
        # Get optional parameters
        file_type = sys.argv[2] if len(sys.argv) > 2 else 'txt'
        email_column = 0  # Always use column 1 (index 0) for emails/domains
        
        # Create analyzer instance
        analyzer = EmailDomainAnalyzer()
        
        # Load entries from file
        entries = analyzer.load_entries_from_file(input_file, file_type, email_column)
        if not entries:
            print("No entries found. Exiting.")
            return
            
        # Generate output filename
        output_csv = analyzer.generate_output_filename(input_file)
        print(f"\nAnalysis will be written to: {output_csv}")
        
        # Start timing
        start_time = time.time()
        
        # Process all entries using the optimized unique-domain approach
        await analyzer.process_entries_async(entries, output_csv)
        
        # Calculate and print execution time
        elapsed_time = time.time() - start_time
        print(f"\nCompleted in {elapsed_time:.2f} seconds")
        print(f"Results saved to '{output_csv}'")
        
    except KeyboardInterrupt:
        print("\nInterrupted by user")
    except Exception as e:
        print(f"Error: {e}")
        logging.error(f"Application error: {e}")
    finally:
        if analyzer:
            await analyzer.cleanup()
            await analyzer.db.cleanup()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nExiting...")
