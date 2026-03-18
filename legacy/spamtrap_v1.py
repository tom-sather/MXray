#!/usr/bin/env python3
import argparse
import asyncio
import csv
import hashlib
import json
import logging
import os
import re
import sys
import time
import uuid
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

import dns.resolver

try:
    import aiohttp
except ImportError:  # pragma: no cover - runtime fallback
    aiohttp = None


logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s: %(message)s",
    handlers=[logging.StreamHandler()],
)

BATCH_SIZE = 200
QUERY_TIMEOUT = 5
DNS_CONCURRENCY = 20
PROCESS_ID = str(uuid.uuid4())[:8]
EMAIL_REGEX = re.compile(r"^[^@\s]+@[^@\s]+\.[a-zA-Z]{2,}$")
DOMAIN_REGEX = re.compile(r"^[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")
LOCALPART_ALPHA_DIGITS_REGEX = re.compile(r"^[A-Za-z]+[0-9]+$")


class LRUCache:
    def __init__(self, capacity: int = 50000):
        self.capacity = capacity
        self.cache: Dict[str, object] = {}
        self.order: List[str] = []

    def get(self, key: str):
        if key not in self.cache:
            return None
        self.order.remove(key)
        self.order.append(key)
        return self.cache[key]

    def set(self, key: str, value) -> None:
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


DNS_CACHE = LRUCache(50000)
WEB_CACHE = LRUCache(50000)


def normalize_host_from_url(url: str) -> str:
    if not url:
        return ""
    try:
        parsed = urlparse(url)
        return (parsed.hostname or "").lower().rstrip(".")
    except Exception:
        return ""


def root_domain(host: str) -> str:
    host = host.lower().strip(".")
    if not host:
        return ""
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    # Lightweight fallback (no publicsuffix dependency).
    return ".".join(parts[-2:])


def is_valid_domain(domain: str) -> bool:
    return bool(re.match(r"^[a-z0-9.-]+\.[a-z]{2,}$", domain))


def load_rules_config(config_path: str) -> Dict:
    with open(config_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    required_top_level = {
        "known_trap_mx_patterns",
        "known_disposable_mx_patterns",
        "typo_exempt_domains",
        "suppression_exempt_domains",
        "score_weights",
        "risk_band_thresholds",
        "dns_error_score_cap",
        "web_check",
        "web_scoring_weights",
    }
    missing = required_top_level - set(data.keys())
    if missing:
        raise ValueError(f"Missing keys in rules config: {sorted(missing)}")

    return data


def load_suppression_domains(suppression_path: str) -> Set[str]:
    domains: Set[str] = set()
    if not os.path.exists(suppression_path):
        return domains

    with open(suppression_path, "r", encoding="utf-8") as f:
        for line in f:
            value = line.strip().lower()
            if not value:
                continue
            first_col = value.split(",", 1)[0].strip().rstrip(".")
            if first_col and is_valid_domain(first_col):
                domains.add(first_col)

    return domains


def load_provider_domains(file_path: str, provider: str) -> Dict[str, str]:
    domains: Dict[str, str] = {}
    if not os.path.exists(file_path):
        return domains

    delimiter = "\t" if file_path.lower().endswith(".tsv") else ","

    with open(file_path, "r", encoding="utf-8", newline="") as f:
        reader = csv.reader(f, delimiter=delimiter)
        header = next(reader, None)

        domain_idx = 0
        if header:
            lowered = [h.strip().lower() for h in header]
            if "domain" in lowered:
                domain_idx = lowered.index("domain")
            else:
                first = header[0].strip().lower().rstrip(".")
                if is_valid_domain(first):
                    domains[first] = provider

        for row in reader:
            if not row or len(row) <= domain_idx:
                continue
            domain = row[domain_idx].strip().lower().rstrip(".")
            if not domain or "@" in domain:
                continue
            if is_valid_domain(domain):
                domains[domain] = provider

    return domains


def build_major_provider_domains(provider_files: List[Tuple[str, str]]) -> Dict[str, str]:
    merged: Dict[str, str] = {}
    for path, provider in provider_files:
        merged.update(load_provider_domains(path, provider))
    return merged


def one_edit_or_adjacent_transpose_away(a: str, b: str) -> bool:
    if a == b:
        return False
    la, lb = len(a), len(b)
    if abs(la - lb) > 1:
        return False

    if la == lb:
        mismatches: List[int] = []
        for i, (ca, cb) in enumerate(zip(a, b)):
            if ca != cb:
                mismatches.append(i)
                if len(mismatches) > 2:
                    return False

        if len(mismatches) == 1:
            return True
        if len(mismatches) == 2:
            i, j = mismatches
            return j == i + 1 and a[i] == b[j] and a[j] == b[i]
        return False

    if la > lb:
        a, b = b, a
        la, lb = lb, la

    i = 0
    j = 0
    used_skip = False
    while i < la and j < lb:
        if a[i] == b[j]:
            i += 1
            j += 1
            continue
        if used_skip:
            return False
        used_skip = True
        j += 1

    return True


def parse_input_entry(entry: str) -> Tuple[Optional[str], Optional[str], Optional[str], Optional[str], Optional[str]]:
    entry = entry.strip()
    if not entry:
        return None, None, None, None, "empty_input"

    if "@" not in entry:
        if DOMAIN_REGEX.match(entry):
            domain = entry.lower().rstrip(".")
            return "", domain, domain, "domain", None
        return None, None, None, None, "invalid_email_format"

    if not EMAIL_REGEX.match(entry):
        return None, None, None, None, "invalid_email_format"

    localpart, domain = entry.rsplit("@", 1)
    localpart = localpart.lower()
    domain = domain.lower().rstrip(".")
    normalized_email = f"{localpart}@{domain}"
    return localpart, domain, normalized_email, "email", None


class WebsiteSignalChecker:
    def __init__(
        self,
        timeout_seconds: float,
        max_redirects: int,
        retry_count: int,
        parking_keywords: List[str],
        parking_service_domains: List[str],
        redirect_suspicious_min_external_hops: int,
    ):
        self.timeout_seconds = timeout_seconds
        self.max_redirects = max_redirects
        self.retry_count = retry_count
        self.parking_keywords = [k.lower() for k in parking_keywords]
        self.parking_service_domains = [d.lower() for d in parking_service_domains]
        self.redirect_suspicious_min_external_hops = redirect_suspicious_min_external_hops
        self.session = None
        self.logger = logging.getLogger(__name__)

    async def setup(self) -> None:
        if aiohttp is None:
            return
        if self.session is None:
            timeout = aiohttp.ClientTimeout(total=self.timeout_seconds)
            connector = aiohttp.TCPConnector(limit=100, ttl_dns_cache=300, use_dns_cache=True)
            self.session = aiohttp.ClientSession(timeout=timeout, connector=connector)

    async def cleanup(self) -> None:
        if self.session:
            await self.session.close()
            self.session = None

    async def fetch_url_sequence(self, domain: str) -> Dict:
        cache_key = f"web:{domain}"
        cached = WEB_CACHE.get(cache_key)
        if cached is not None:
            return cached

        if self.session is None:
            result = {
                "web_checked": False,
                "web_state": "unknown",
                "web_final_url": "",
                "web_checked_host": "",
                "web_redirect_hops": 0,
                "web_external_redirect_hops": 0,
                "web_reason": "web_checker_unavailable",
                "web_error": "aiohttp_not_available",
            }
            WEB_CACHE.set(cache_key, result)
            return result

        checked_hosts = [domain]
        rd = root_domain(domain)
        if rd and rd != domain:
            checked_hosts.append(rd)
        last_error = ""

        for checked_host in checked_hosts:
            attempts = [f"http://{checked_host}", f"https://{checked_host}"]
            for url in attempts:
                for _ in range(self.retry_count):
                    started = time.time()
                    try:
                        async with self.session.get(url, allow_redirects=True, max_redirects=self.max_redirects) as resp:
                            history_urls = [str(h.url) for h in resp.history]
                            final_url = str(resp.url)
                            chain = history_urls + [final_url]
                            body = await resp.text(errors="ignore")
                            elapsed = time.time() - started

                            result = self.classify_web_state(domain, chain, body, elapsed)
                            result["web_checked_host"] = checked_host
                            if checked_host != domain:
                                result["web_reason"] = f"{result.get('web_reason', 'web_check')};fallback_root_domain"
                            WEB_CACHE.set(cache_key, result)
                            return result
                    except Exception as e:  # network volatility expected
                        last_error = str(e)

        result = {
            "web_checked": True,
            "web_state": "dead",
            "web_final_url": "",
            "web_checked_host": checked_hosts[-1] if checked_hosts else domain,
            "web_redirect_hops": 0,
            "web_external_redirect_hops": 0,
            "web_reason": "unreachable",
            "web_error": last_error[:200],
        }
        WEB_CACHE.set(cache_key, result)
        return result

    def classify_web_state(self, domain: str, chain: List[str], body: str, elapsed: float) -> Dict:
        final_url = chain[-1] if chain else ""
        redirect_hops = max(0, len(chain) - 1)

        external_hops = 0
        original_root = root_domain(domain)
        for step_url in chain[1:]:
            host = normalize_host_from_url(step_url)
            if root_domain(host) and root_domain(host) != original_root:
                external_hops += 1

        body_lower = (body or "").lower()
        final_host = normalize_host_from_url(final_url)
        final_url_lower = final_url.lower()

        # Parking service detection on redirect destination.
        if any(service in final_host or service in final_url_lower for service in self.parking_service_domains):
            return {
                "web_checked": True,
                "web_state": "parked",
                "web_final_url": final_url,
                "web_redirect_hops": redirect_hops,
                "web_external_redirect_hops": external_hops,
                "web_reason": "parking_service_redirect",
                "web_elapsed_seconds": round(elapsed, 3),
            }

        keyword_hits = [k for k in self.parking_keywords if k in body_lower]
        if keyword_hits:
            parking_like = [
                "domain is parked",
                "domain for sale",
                "buy this domain",
                "parkingcrew",
                "sedo",
                "afternic",
                "hugedomains",
            ]
            construction_like = [
                "under construction",
                "coming soon",
                "future home of",
                "website coming soon",
            ]

            if any(k in body_lower for k in parking_like):
                return {
                    "web_checked": True,
                    "web_state": "parked",
                    "web_final_url": final_url,
                    "web_redirect_hops": redirect_hops,
                    "web_external_redirect_hops": external_hops,
                    "web_reason": "parking_keywords_detected",
                    "web_elapsed_seconds": round(elapsed, 3),
                }

            if any(k in body_lower for k in construction_like):
                return {
                    "web_checked": True,
                    "web_state": "under_construction",
                    "web_final_url": final_url,
                    "web_redirect_hops": redirect_hops,
                    "web_external_redirect_hops": external_hops,
                    "web_reason": "construction_keywords_detected",
                    "web_elapsed_seconds": round(elapsed, 3),
                }

        if (
            redirect_hops >= 2
            and external_hops >= self.redirect_suspicious_min_external_hops
        ):
            return {
                "web_checked": True,
                "web_state": "redirect_suspicious",
                "web_final_url": final_url,
                "web_redirect_hops": redirect_hops,
                "web_external_redirect_hops": external_hops,
                "web_reason": "external_redirect_chain",
                "web_elapsed_seconds": round(elapsed, 3),
            }

        return {
            "web_checked": True,
            "web_state": "live",
            "web_final_url": final_url,
            "web_redirect_hops": redirect_hops,
            "web_external_redirect_hops": external_hops,
            "web_reason": "live_or_unknown_content",
            "web_elapsed_seconds": round(elapsed, 3),
        }


class SpamTrapDetector:
    def __init__(
        self,
        rules: Dict,
        suppression_domains: Set[str],
        major_provider_domains: Dict[str, str],
        web_check_mode: str,
        web_check_min_pre_score: Optional[int],
        web_timeout_override: Optional[float],
    ):
        self.rules = rules
        self.dns_semaphore = asyncio.Semaphore(DNS_CONCURRENCY)
        self.logger = logging.getLogger(__name__)
        self.cache_hits = 0
        self.cache_misses = 0
        self.suppression_domains = suppression_domains
        self.major_provider_domains = major_provider_domains

        self.known_trap_patterns = [x.lower() for x in rules["known_trap_mx_patterns"]]
        self.known_disposable_patterns = [x.lower() for x in rules["known_disposable_mx_patterns"]]
        self.typo_exempt_domains = {x.lower().rstrip(".") for x in rules.get("typo_exempt_domains", [])}
        self.suppression_exempt_domains = {x.lower().rstrip(".") for x in rules.get("suppression_exempt_domains", [])}
        self.weights = rules["score_weights"]
        self.thresholds = rules["risk_band_thresholds"]
        self.dns_error_cap = int(rules["dns_error_score_cap"])

        self.web_cfg = rules["web_check"]
        self.web_weights = rules["web_scoring_weights"]

        self.web_mode = web_check_mode if web_check_mode else self.web_cfg.get("mode_default", "gated")
        self.web_min_pre_score = (
            int(web_check_min_pre_score)
            if web_check_min_pre_score is not None
            else int(self.web_cfg.get("web_check_min_pre_score", 60))
        )
        timeout_seconds = (
            float(web_timeout_override)
            if web_timeout_override is not None
            else float(self.web_cfg.get("timeout_seconds", 4.0))
        )
        max_redirects = int(self.web_cfg.get("max_redirects", 5))
        retry_count = int(self.web_cfg.get("retry_count", 1))

        self.major_domains_by_tld: Dict[str, List[str]] = {}
        for domain in self.major_provider_domains.keys():
            tld = domain.rsplit(".", 1)[-1]
            self.major_domains_by_tld.setdefault(tld, []).append(domain)

        self.website_checker = None
        if self.web_mode != "off" and aiohttp is not None:
            self.website_checker = WebsiteSignalChecker(
                timeout_seconds=timeout_seconds,
                max_redirects=max_redirects,
                retry_count=retry_count,
                parking_keywords=self.web_cfg.get("parking_keywords", []),
                parking_service_domains=self.web_cfg.get("parking_service_domains", []),
                redirect_suspicious_min_external_hops=int(
                    self.web_cfg.get("redirect_suspicious_min_external_hops", 2)
                ),
            )
        elif self.web_mode != "off" and aiohttp is None:
            self.logger.warning("aiohttp is not installed; forcing web check mode to 'off'.")
            self.web_mode = "off"

    def is_major_mailbox_domain(self, domain: str) -> bool:
        domain = domain.lower().rstrip(".")
        if domain in self.major_provider_domains:
            return True
        rd = root_domain(domain)
        return rd in self.major_provider_domains

    def is_suppression_exempt_domain(self, domain: str) -> bool:
        domain = domain.lower().rstrip(".")
        if domain in self.suppression_exempt_domains:
            return True
        rd = root_domain(domain)
        return rd in self.suppression_exempt_domains

    async def setup(self) -> None:
        if self.website_checker:
            await self.website_checker.setup()

    async def cleanup(self) -> None:
        if self.website_checker:
            await self.website_checker.cleanup()

    async def check_mx(self, domain: str) -> Tuple[List[str], bool]:
        key = f"mx:{domain}"
        cached = DNS_CACHE.get(key)
        if cached is not None:
            self.cache_hits += 1
            return cached

        self.cache_misses += 1
        loop = asyncio.get_running_loop()

        async with self.dns_semaphore:
            def _resolve():
                try:
                    answers = dns.resolver.resolve(domain, "MX", lifetime=QUERY_TIMEOUT)
                    records = sorted(str(r.exchange).rstrip(".") for r in answers)
                    return records, False
                except Exception as e:
                    self.logger.debug("MX lookup failed for %s: %s", domain, e)
                    return [], True

            result = await loop.run_in_executor(None, _resolve)

        DNS_CACHE.set(key, result)
        return result

    async def check_a(self, domain: str) -> Tuple[List[str], bool]:
        key = f"a:{domain}"
        cached = DNS_CACHE.get(key)
        if cached is not None:
            self.cache_hits += 1
            return cached

        self.cache_misses += 1
        loop = asyncio.get_running_loop()

        async with self.dns_semaphore:
            def _resolve():
                try:
                    answers = dns.resolver.resolve(domain, "A", lifetime=QUERY_TIMEOUT)
                    records = sorted(str(r.address) for r in answers)
                    return records, False
                except Exception as e:
                    self.logger.debug("A lookup failed for %s: %s", domain, e)
                    return [], True

            result = await loop.run_in_executor(None, _resolve)

        DNS_CACHE.set(key, result)
        return result

    async def check_txt(self, domain: str, record_type: str) -> Tuple[Optional[str], bool]:
        key = f"txt:{record_type}:{domain}"
        cached = DNS_CACHE.get(key)
        if cached is not None:
            self.cache_hits += 1
            return cached

        self.cache_misses += 1
        loop = asyncio.get_running_loop()

        async with self.dns_semaphore:
            def _resolve():
                try:
                    answers = dns.resolver.resolve(domain, "TXT", lifetime=QUERY_TIMEOUT)
                    for record in answers:
                        txt = "".join(s.decode("utf-8") for s in record.strings)
                        if record_type == "spf" and "v=spf1" in txt:
                            return txt, False
                        if record_type == "dmarc" and "v=DMARC1" in txt:
                            return txt, False
                    return None, False
                except Exception as e:
                    self.logger.debug("TXT %s lookup failed for %s: %s", record_type, domain, e)
                    return None, True

            result = await loop.run_in_executor(None, _resolve)

        DNS_CACHE.set(key, result)
        return result

    async def get_domain_dns(self, domain: str) -> Dict:
        mx_records, mx_err = await self.check_mx(domain)
        a_records, a_err = await self.check_a(domain)
        spf_record, spf_err = await self.check_txt(domain, "spf")
        dmarc_record, dmarc_err = await self.check_txt(f"_dmarc.{domain}", "dmarc")
        mx_primary_host = mx_records[0].lower() if mx_records else ""
        mx_provider = self.categorize_mx_provider(mx_primary_host)

        has_mx = bool(mx_records)
        has_a = bool(a_records)
        has_spf = spf_record is not None
        has_dmarc = dmarc_record is not None

        dns_lookup_error = (mx_err and a_err) or (not has_mx and not has_a and (mx_err or a_err))
        txt_lookup_error = spf_err and dmarc_err

        return {
            "domain": domain,
            "mx_records": mx_records,
            "mx_primary_host": mx_primary_host,
            "mx_provider": mx_provider,
            "a_records": a_records,
            "spf_record": spf_record,
            "dmarc_record": dmarc_record,
            "has_mx": has_mx,
            "has_a": has_a,
            "has_spf": has_spf,
            "has_dmarc": has_dmarc,
            "dns_lookup_error": dns_lookup_error,
            "txt_lookup_error": txt_lookup_error,
        }

    @staticmethod
    def categorize_mx_provider(mx_host: str) -> str:
        mx_lower = (mx_host or "").lower()
        if not mx_lower:
            return "No MX"
        if any(x in mx_lower for x in ["google", "gmail", "googlemail", "aspmx", "gsuite"]):
            return "Google"
        if any(x in mx_lower for x in ["outlook", "hotmail", "office365", "microsoft", "protection.outlook", "exchange-online", "msft"]):
            return "Microsoft"
        if any(x in mx_lower for x in ["ymail", "yahoo", "yahoodns"]):
            return "Yahoo"
        if any(x in mx_lower for x in ["pp-hosted", "ppe-hosted", "pphosted", "ppsmtp", "proofpoint"]):
            return "Proofpoint"
        if "mailgun" in mx_lower:
            return "Mailgun"
        if any(x in mx_lower for x in ["icloud", "me.com", "mac.com", "apple"]):
            return "Apple"
        if "zoho" in mx_lower:
            return "Zoho"
        if "fastmail" in mx_lower:
            return "Fastmail"
        if any(x in mx_lower for x in ["protonmail", "proton.me", "pm.me"]):
            return "ProtonMail"
        if any(x in mx_lower for x in ["privateemail", "namecheap"]):
            return "Namecheap"
        if any(x in mx_lower for x in ["ovh", "mail.ovh.net"]):
            return "OVH"
        if any(x in mx_lower for x in ["amazonses", "aws", "ses"]):
            return "Amazon SES"
        if any(x in mx_lower for x in ["mimecast", "barracuda", "ironport", "cisco"]):
            return "Security Gateway"
        return "Custom/Other"

    @staticmethod
    def match_pattern(mx_records: List[str], patterns: List[str]) -> Optional[str]:
        if not mx_records:
            return None
        for mx in mx_records:
            mx_l = mx.lower()
            for pattern in patterns:
                if pattern == mx_l or pattern in mx_l:
                    return pattern
        return None

    def detect_typo_domain(self, domain: str) -> Tuple[bool, str, str]:
        domain = domain.lower()
        if domain in self.typo_exempt_domains:
            return False, "", ""
        if domain in self.major_provider_domains:
            return False, "", ""

        tld = domain.rsplit(".", 1)[-1] if "." in domain else ""
        candidates = self.major_domains_by_tld.get(tld, [])
        for candidate in candidates:
            if abs(len(candidate) - len(domain)) > 1:
                continue
            if one_edit_or_adjacent_transpose_away(domain, candidate):
                provider = self.major_provider_domains.get(candidate, "MajorProvider")
                return True, candidate, provider

        return False, "", ""

    def extract_core_features(self, localpart: str, dns: Dict) -> Dict:
        mx_records = dns.get("mx_records", [])
        has_mx = dns.get("has_mx", False)
        has_a = dns.get("has_a", False)
        has_spf = dns.get("has_spf", False)
        has_dmarc = dns.get("has_dmarc", False)
        dns_lookup_error = dns.get("dns_lookup_error", False)
        domain = dns.get("domain", "").lower()

        localpart_len = len(localpart)
        alpha_prefix_num_suffix = bool(LOCALPART_ALPHA_DIGITS_REGEX.match(localpart))
        len10_letters_digits = alpha_prefix_num_suffix and localpart_len == 10

        known_trap_match = self.match_pattern(mx_records, self.known_trap_patterns)
        disposable_match = self.match_pattern(mx_records, self.known_disposable_patterns)
        suppression_domain_match = (
            domain in self.suppression_domains
            and not self.is_major_mailbox_domain(domain)
            and not self.is_suppression_exempt_domain(domain)
        )
        typo_domain_match, typo_canonical_domain, typo_provider = self.detect_typo_domain(domain)
        letters = sum(1 for c in localpart if c.isalpha())
        digits = sum(1 for c in localpart if c.isdigit())
        alnum_only = localpart.isalnum() if localpart else False
        disposamail_pattern_match = (
            len(localpart) == 10
            and alnum_only
            and 5 <= letters <= 7
            and 3 <= digits <= 5
            and letters + digits == 10
            and domain.endswith(".com")
            and not self.is_major_mailbox_domain(domain)
        )

        domain_no_mx_no_a = not has_mx and not has_a
        domain_has_auth_but_no_delivery = (has_spf or has_dmarc) and domain_no_mx_no_a

        return {
            "localpart_len": localpart_len,
            "localpart_pattern_letters_then_digits_len10": len10_letters_digits,
            "localpart_alpha_prefix_num_suffix": alpha_prefix_num_suffix,
            "known_trap_match": known_trap_match,
            "disposable_match": disposable_match,
            "suppression_domain_match": suppression_domain_match,
            "disposamail_pattern_match": disposamail_pattern_match,
            "typo_domain_match": typo_domain_match,
            "typo_canonical_domain": typo_canonical_domain,
            "typo_domain_provider": typo_provider,
            "domain_no_mx_no_a": domain_no_mx_no_a,
            "domain_has_auth_but_no_delivery": domain_has_auth_but_no_delivery,
            "dns_lookup_error": dns_lookup_error,
            "txt_lookup_error": dns.get("txt_lookup_error", False),
        }

    def core_feature_flags(self, features: Dict, infra_risky: bool = False, cohort_flags: Optional[Dict] = None) -> Dict[str, bool]:
        cohort_flags = cohort_flags or {}
        return {
            "suppression_domain_match": features["suppression_domain_match"],
            "disposamail_pattern_match": features["disposamail_pattern_match"],
            "typo_domain_near_major_provider": features["typo_domain_match"],
            "localpart_len_10_letters_digits": features["localpart_pattern_letters_then_digits_len10"],
            "localpart_alpha_prefix_num_suffix": features["localpart_alpha_prefix_num_suffix"],
            "mx_matches_known_trap_network": features["known_trap_match"] is not None,
            "mx_matches_disposable_network": features["disposable_match"] is not None,
            "domain_no_mx_no_a": features["domain_no_mx_no_a"],
            "domain_has_auth_but_no_delivery": features["domain_has_auth_but_no_delivery"],
            "dns_lookup_error": features["dns_lookup_error"],
            "infra_cluster_risky_neighbors": infra_risky,
            "cohort_typo_density_anomaly": cohort_flags.get("cohort_typo_density_anomaly", False),
            "cohort_risky_cluster_anomaly": cohort_flags.get("cohort_risky_cluster_anomaly", False),
        }

    @staticmethod
    def score_feature_flags(feature_flags: Dict[str, bool], weights: Dict[str, int]) -> Tuple[int, List[str]]:
        score = 0
        reasons: List[str] = []
        for feature_name, enabled in feature_flags.items():
            if enabled:
                score += int(weights.get(feature_name, 0))
                reasons.append(feature_name)
        return score, reasons

    def apply_dns_score_cap(self, score: int, features: Dict, reason_codes: List[str]) -> int:
        score = min(100, score)
        has_high_confidence_non_web = features["suppression_domain_match"] or (features["known_trap_match"] is not None)
        if features["dns_lookup_error"] and score > self.dns_error_cap and not has_high_confidence_non_web:
            score = self.dns_error_cap
            reason_codes.append("score_capped_due_to_dns_error")
        return score

    def score_web_supportive(self, web_result: Dict) -> Tuple[int, List[str], Dict[str, bool]]:
        if not web_result.get("web_checked", False):
            return 0, [], {
                "website_parked_or_for_sale": False,
                "website_under_construction": False,
                "website_redirect_suspicious": False,
                "website_unreachable": False,
            }

        web_state = web_result.get("web_state", "unknown")
        web_feature_flags = {
            "website_parked_or_for_sale": web_state == "parked",
            "website_under_construction": web_state == "under_construction",
            "website_redirect_suspicious": web_state == "redirect_suspicious",
            "website_unreachable": web_state in ("dead", "unknown"),
        }
        web_score = 0
        reasons: List[str] = []
        for feature_name, enabled in web_feature_flags.items():
            if enabled:
                web_score += int(self.web_weights.get(feature_name, 0))
                reasons.append(feature_name)
        return web_score, reasons, web_feature_flags

    def build_infra_clusters(self, domain_dns_map: Dict[str, Dict]) -> Dict[str, Dict]:
        clusters: Dict[str, List[str]] = {}
        domain_has_risky_anchor: Dict[str, bool] = {}

        for domain, dns in domain_dns_map.items():
            mx_records = dns.get("mx_records", [])
            signature = "|".join(sorted(r.lower() for r in mx_records))
            if not signature:
                signature = f"no_mx::{domain.rsplit('.', 1)[-1]}"
            clusters.setdefault(signature, []).append(domain)

            known_trap = self.match_pattern(mx_records, self.known_trap_patterns) is not None
            suppression = domain in self.suppression_domains
            domain_has_risky_anchor[domain] = known_trap or suppression

        domain_cluster_map: Dict[str, Dict] = {}
        for signature, domains in clusters.items():
            risky_anchor_present = any(domain_has_risky_anchor.get(d, False) for d in domains)
            cluster_size = len(domains)

            if risky_anchor_present and cluster_size >= 2:
                risk = "high"
            elif risky_anchor_present:
                risk = "medium"
            else:
                risk = "low"

            cluster_id = hashlib.sha1(signature.encode("utf-8")).hexdigest()[:10]
            for domain in domains:
                domain_cluster_map[domain] = {
                    "infra_cluster_id": cluster_id,
                    "infra_cluster_risk": risk,
                    "infra_cluster_risky_neighbors": risk in {"high", "medium"} and not domain_has_risky_anchor.get(domain, False),
                }

        return domain_cluster_map

    @staticmethod
    def compute_cohort_flags(row_feature_records: List[Dict], min_rows: int = 50, typo_ratio_threshold: float = 0.05, risky_cluster_ratio_threshold: float = 0.08) -> Dict[str, bool]:
        valid_rows = [r for r in row_feature_records if not r.get("invalid")]
        if len(valid_rows) < min_rows:
            return {
                "cohort_typo_density_anomaly": False,
                "cohort_risky_cluster_anomaly": False,
            }

        typo_count = sum(1 for r in valid_rows if r["features"]["typo_domain_match"])
        typo_ratio = typo_count / len(valid_rows)

        risky_cluster_count = sum(
            1 for r in valid_rows if r.get("infra_cluster_risk") in {"high", "medium"}
        )
        risky_cluster_ratio = risky_cluster_count / len(valid_rows)

        return {
            "cohort_typo_density_anomaly": typo_ratio >= typo_ratio_threshold,
            "cohort_risky_cluster_anomaly": risky_cluster_ratio >= risky_cluster_ratio_threshold,
        }

    async def run_website_checks(self, domains: List[str]) -> Dict[str, Dict]:
        results: Dict[str, Dict] = {}
        if not domains or self.web_mode == "off" or self.website_checker is None:
            return results

        tasks = [self.website_checker.fetch_url_sequence(domain) for domain in domains]
        batch_results = await asyncio.gather(*tasks, return_exceptions=True)
        for domain, result in zip(domains, batch_results):
            if isinstance(result, Exception):
                results[domain] = {
                    "web_checked": True,
                    "web_state": "unknown",
                    "web_final_url": "",
                    "web_checked_host": domain,
                    "web_redirect_hops": 0,
                    "web_external_redirect_hops": 0,
                    "web_reason": f"web_check_error:{str(result)[:120]}",
                }
            else:
                results[domain] = result
        return results

    async def process_entries_async(self, entries: List[str], output_csv: str, unique_domains_path: str) -> None:
        await self.setup()
        try:
            parsed_rows = []
            unique_domains: Set[str] = set()
            for raw in entries:
                localpart, domain, normalized_email, input_type, parse_error = parse_input_entry(raw)
                parsed_rows.append(
                    {
                        "raw": raw.strip(),
                        "localpart": localpart,
                        "domain": domain,
                        "normalized_email": normalized_email,
                        "input_type": input_type,
                        "parse_error": parse_error,
                    }
                )
                if domain:
                    unique_domains.add(domain)

            with open(unique_domains_path, "w", encoding="utf-8") as f:
                for domain in sorted(unique_domains):
                    f.write(f"{domain}\n")

            print(f"Total input rows: {len(parsed_rows)}")
            print(f"Unique valid domains to resolve: {len(unique_domains)}")
            print(f"Unique domains file: {unique_domains_path}")
            print(f"Web check mode: {self.web_mode}")

            domain_dns_map: Dict[str, Dict] = {}
            with open(unique_domains_path, "r", encoding="utf-8") as f:
                domain_list = [line.strip() for line in f if line.strip()]

            for i in range(0, len(domain_list), BATCH_SIZE):
                batch = domain_list[i:i + BATCH_SIZE]
                tasks = [self.get_domain_dns(domain) for domain in batch]
                results = await asyncio.gather(*tasks, return_exceptions=True)
                for domain, result in zip(batch, results):
                    if isinstance(result, Exception):
                        self.logger.error("DNS resolution failure for %s: %s", domain, result)
                        domain_dns_map[domain] = {
                            "domain": domain,
                            "mx_records": [],
                            "mx_primary_host": "",
                            "mx_provider": "No MX",
                            "a_records": [],
                            "spf_record": None,
                            "dmarc_record": None,
                            "has_mx": False,
                            "has_a": False,
                            "has_spf": False,
                            "has_dmarc": False,
                            "dns_lookup_error": True,
                            "txt_lookup_error": True,
                        }
                    else:
                        domain_dns_map[domain] = result

                print(f"Resolved batch {i // BATCH_SIZE + 1}: {min(i + len(batch), len(domain_list))}/{len(domain_list)} domains")

            infra_map = self.build_infra_clusters(domain_dns_map)

            row_feature_records: List[Dict] = []
            domain_pre_scores: Dict[str, int] = {}
            domain_has_high_signal: Dict[str, bool] = {}

            # First pass: compute core features and provisional pre-web scores.
            for row in parsed_rows:
                if row["parse_error"]:
                    row_feature_records.append({"invalid": True, "row": row})
                    continue

                domain = row["domain"]
                localpart = row["localpart"] or ""
                dns = domain_dns_map.get(domain, {})
                features = self.extract_core_features(localpart, dns)
                infra = infra_map.get(
                    domain,
                    {
                        "infra_cluster_id": "",
                        "infra_cluster_risk": "low",
                        "infra_cluster_risky_neighbors": False,
                    },
                )
                core_flags = self.core_feature_flags(
                    features,
                    infra_risky=infra["infra_cluster_risky_neighbors"],
                    cohort_flags=None,
                )
                pre_score, pre_reasons = self.score_feature_flags(core_flags, self.weights)
                pre_score = self.apply_dns_score_cap(pre_score, features, pre_reasons)

                domain_pre_scores[domain] = max(pre_score, domain_pre_scores.get(domain, 0))
                domain_has_high_signal[domain] = domain_has_high_signal.get(domain, False) or (
                    features["suppression_domain_match"] or features["known_trap_match"] is not None
                )

                row_feature_records.append(
                    {
                        "invalid": False,
                        "row": row,
                        "dns": dns,
                        "features": features,
                        "infra": infra,
                        "pre_score_no_cohort": pre_score,
                        "pre_reasons_no_cohort": pre_reasons,
                    }
                )

            cohort_cfg = self.rules.get("cohort_anomaly", {})
            cohort_flags = self.compute_cohort_flags(
                row_feature_records,
                min_rows=int(cohort_cfg.get("min_rows", 50)),
                typo_ratio_threshold=float(cohort_cfg.get("typo_ratio_threshold", 0.05)),
                risky_cluster_ratio_threshold=float(cohort_cfg.get("risky_cluster_ratio_threshold", 0.08)),
            )

            # Recompute pre score with cohort flags included.
            for item in row_feature_records:
                if item.get("invalid"):
                    continue
                features = item["features"]
                infra = item["infra"]
                core_flags = self.core_feature_flags(
                    features,
                    infra_risky=infra["infra_cluster_risky_neighbors"],
                    cohort_flags=cohort_flags,
                )
                pre_score, pre_reasons = self.score_feature_flags(core_flags, self.weights)
                pre_score = self.apply_dns_score_cap(pre_score, features, pre_reasons)
                item["core_flags"] = core_flags
                item["pre_score"] = pre_score
                item["pre_reasons"] = pre_reasons

                domain = item["row"]["domain"]
                domain_pre_scores[domain] = max(pre_score, domain_pre_scores.get(domain, 0))

            # Decide website-check candidates.
            if self.web_mode == "all":
                candidate_domains = {
                    d for d in domain_list if not self.is_major_mailbox_domain(d)
                }
            elif self.web_mode == "gated":
                candidate_domains = {
                    d
                    for d in domain_list
                    if not self.is_major_mailbox_domain(d)
                    and (
                        domain_pre_scores.get(d, 0) >= self.web_min_pre_score
                        or domain_has_high_signal.get(d, False)
                    )
                }
            else:
                candidate_domains = set()

            print(f"Website checks scheduled: {len(candidate_domains)} domains")
            web_results = await self.run_website_checks(sorted(candidate_domains))

            output_rows: List[Dict] = []
            for item in row_feature_records:
                if item.get("invalid"):
                    row = item["row"]
                    output_rows.append(
                        {
                            "original_input": row["raw"],
                            "email": row["raw"],
                        "domain": "",
                        "mx_records": "",
                        "mx_primary_host": "",
                        "mx_provider": "No MX",
                        "has_mx": False,
                            "has_a": False,
                            "has_spf": False,
                            "has_dmarc": False,
                            "localpart_len": 0,
                            "localpart_pattern_letters_then_digits_len10": False,
                            "localpart_alpha_prefix_num_suffix": False,
                            "suppression_domain_match": False,
                            "disposamail_pattern_match": False,
                            "typo_domain_match": False,
                            "typo_domain_provider": "",
                            "typo_canonical_domain": "",
                            "mx_known_trap_match": "",
                            "mx_disposable_match": "",
                            "web_checked": False,
                            "web_state": "unknown",
                            "web_final_url": "",
                            "web_checked_host": "",
                            "web_redirect_hops": 0,
                            "web_external_redirect_hops": 0,
                            "web_reason": "",
                            "infra_cluster_id": "",
                            "infra_cluster_risk": "low",
                            "dns_lifecycle_signal": "not_available",
                            "cohort_typo_density_anomaly": cohort_flags.get("cohort_typo_density_anomaly", False),
                            "cohort_risky_cluster_anomaly": cohort_flags.get("cohort_risky_cluster_anomaly", False),
                            "risk_score": 0,
                            "pre_web_score": 0,
                            "ml_ranker_placeholder_score": 0.0,
                            "risk_band": "Low",
                            "reason_codes": row["parse_error"],
                            "analyst_label": "",
                            "feedback_record_id": "",
                            "status": "Clear",
                        }
                    )
                    continue

                row = item["row"]
                dns = item["dns"]
                features = item["features"]
                infra = item["infra"]

                pre_score = int(item["pre_score"])
                reasons = list(item["pre_reasons"])

                if features["known_trap_match"]:
                    reasons.append(f"mx_known_trap_match:{features['known_trap_match']}")
                if features["disposable_match"]:
                    reasons.append(f"mx_disposable_match:{features['disposable_match']}")
                if features["suppression_domain_match"]:
                    reasons.append("domain_in_suppressions_list")
                if features["typo_domain_match"]:
                    reasons.append(f"typo_domain_candidate:{features['typo_canonical_domain']}")
                    reasons.append(f"typo_domain_provider:{features['typo_domain_provider']}")
                if features["txt_lookup_error"]:
                    reasons.append("txt_lookup_error")

                domain = row["domain"]
                web_result = web_results.get(
                    domain,
                    {
                        "web_checked": False,
                        "web_state": "unknown",
                        "web_final_url": "",
                        "web_checked_host": "",
                        "web_redirect_hops": 0,
                        "web_external_redirect_hops": 0,
                        "web_reason": "web_check_skipped",
                    },
                )

                web_score, web_reasons, _web_flags = self.score_web_supportive(web_result)
                risk_score = min(100, pre_score + web_score)

                has_high_conf_non_web = features["suppression_domain_match"] or (features["known_trap_match"] is not None)
                high_threshold = int(self.thresholds["high"])
                if (
                    risk_score >= high_threshold
                    and pre_score < high_threshold
                    and not has_high_conf_non_web
                    and web_score > 0
                ):
                    risk_score = high_threshold - 1
                    web_reasons.append("web_supportive_cap_applied")

                reasons.extend(web_reasons)

                if row.get("input_type") == "domain":
                    reasons.append("input_type_domain")

                if risk_score >= high_threshold:
                    risk_band = "High"
                elif risk_score >= int(self.thresholds["medium"]):
                    risk_band = "Medium"
                else:
                    risk_band = "Low"

                status = "Flagged" if risk_band in ("High", "Medium") else "Clear"

                output_rows.append(
                    {
                        "original_input": row["raw"],
                        "email": row["normalized_email"] or row["raw"],
                        "domain": dns.get("domain", ""),
                        "mx_records": "|".join(dns.get("mx_records", [])),
                        "mx_primary_host": dns.get("mx_primary_host", ""),
                        "mx_provider": dns.get("mx_provider", "No MX"),
                        "has_mx": dns.get("has_mx", False),
                        "has_a": dns.get("has_a", False),
                        "has_spf": dns.get("has_spf", False),
                        "has_dmarc": dns.get("has_dmarc", False),
                        "localpart_len": features["localpart_len"],
                        "localpart_pattern_letters_then_digits_len10": features[
                            "localpart_pattern_letters_then_digits_len10"
                        ],
                        "localpart_alpha_prefix_num_suffix": features[
                            "localpart_alpha_prefix_num_suffix"
                        ],
                        "suppression_domain_match": features["suppression_domain_match"],
                        "disposamail_pattern_match": features["disposamail_pattern_match"],
                        "typo_domain_match": features["typo_domain_match"],
                        "typo_domain_provider": features["typo_domain_provider"],
                        "typo_canonical_domain": features["typo_canonical_domain"],
                        "mx_known_trap_match": features["known_trap_match"] or "",
                        "mx_disposable_match": features["disposable_match"] or "",
                        "web_checked": web_result.get("web_checked", False),
                        "web_state": web_result.get("web_state", "unknown"),
                        "web_final_url": web_result.get("web_final_url", ""),
                        "web_checked_host": web_result.get("web_checked_host", ""),
                        "web_redirect_hops": web_result.get("web_redirect_hops", 0),
                        "web_external_redirect_hops": web_result.get("web_external_redirect_hops", 0),
                        "web_reason": web_result.get("web_reason", ""),
                        "infra_cluster_id": infra.get("infra_cluster_id", ""),
                        "infra_cluster_risk": infra.get("infra_cluster_risk", "low"),
                        "dns_lifecycle_signal": "not_available",
                        "cohort_typo_density_anomaly": cohort_flags.get("cohort_typo_density_anomaly", False),
                        "cohort_risky_cluster_anomaly": cohort_flags.get("cohort_risky_cluster_anomaly", False),
                        "risk_score": risk_score,
                        "pre_web_score": pre_score,
                        "ml_ranker_placeholder_score": 0.0,
                        "risk_band": risk_band,
                        "reason_codes": ";".join(reasons) if reasons else "none",
                        "analyst_label": "",
                        "feedback_record_id": "",
                        "status": status,
                    }
                )

            self.write_output_csv(output_rows, output_csv)
            print(f"Done. Wrote {len(output_rows)} rows to: {output_csv}")
            print(f"Cache stats: {self.cache_hits} hits, {self.cache_misses} misses")
        finally:
            await self.cleanup()

    @staticmethod
    def write_output_csv(rows: List[Dict], output_csv: str) -> None:
        fieldnames = [
            "original_input",
            "email",
            "domain",
            "mx_records",
            "mx_primary_host",
            "mx_provider",
            "has_mx",
            "has_a",
            "has_spf",
            "has_dmarc",
            "localpart_len",
            "localpart_pattern_letters_then_digits_len10",
            "localpart_alpha_prefix_num_suffix",
            "suppression_domain_match",
            "disposamail_pattern_match",
            "typo_domain_match",
            "typo_domain_provider",
            "typo_canonical_domain",
            "mx_known_trap_match",
            "mx_disposable_match",
            "web_checked",
            "web_state",
            "web_final_url",
            "web_checked_host",
            "web_redirect_hops",
            "web_external_redirect_hops",
            "web_reason",
            "infra_cluster_id",
            "infra_cluster_risk",
            "dns_lifecycle_signal",
            "cohort_typo_density_anomaly",
            "cohort_risky_cluster_anomaly",
            "risk_score",
            "pre_web_score",
            "ml_ranker_placeholder_score",
            "risk_band",
            "reason_codes",
            "analyst_label",
            "feedback_record_id",
            "status",
        ]

        with open(output_csv, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for row in rows:
                writer.writerow(row)


def load_entries_from_file(input_file: str, file_type: str, email_column: int) -> List[str]:
    if not os.path.exists(input_file):
        raise FileNotFoundError(f"Input file not found: {input_file}")

    entries: List[str] = []
    if file_type == "csv":
        with open(input_file, "r", newline="", encoding="utf-8") as f:
            reader = csv.reader(f)
            for row in reader:
                if len(row) > email_column:
                    entries.append(row[email_column].strip())
    else:
        with open(input_file, "r", encoding="utf-8") as f:
            entries = [line.strip() for line in f if line.strip()]

    return entries


def generate_output_filename(input_file: str) -> str:
    base, _ = os.path.splitext(input_file)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"{base}_spamtrap_v2_{ts}_{PROCESS_ID}.csv"


def generate_unique_domains_filename(input_file: str) -> str:
    base, _ = os.path.splitext(input_file)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"{base}_unique_domains_{ts}_{PROCESS_ID}.txt"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Spam Trap Detection Engine v2")
    parser.add_argument("input_file", help="Path to input file")
    parser.add_argument("file_type", nargs="?", default="txt", choices=["txt", "csv"], help="Input format")
    parser.add_argument("email_column", nargs="?", default=0, type=int, help="CSV column index (0-based)")

    parser.add_argument("--web-check-mode", choices=["gated", "all", "off"], default=None)
    parser.add_argument("--web-check-min-pre-score", type=int, default=None)
    parser.add_argument("--web-timeout", type=float, default=None)

    return parser.parse_args()


def main() -> None:
    args = parse_args()

    script_dir = os.path.dirname(os.path.abspath(__file__))
    config_path = os.path.join(script_dir, "spamtrap_rules.json")
    suppression_path = os.path.join(script_dir, "domain_suppressions.csv")

    rules = load_rules_config(config_path)
    suppression_domains = load_suppression_domains(suppression_path)

    provider_files = [
        ("/Users/tomsather/Downloads/Gmail, Microsoft and Yahoo domains - Gmail.csv", "Gmail"),
        ("/Users/tomsather/Downloads/Gmail, Microsoft and Yahoo domains - Yahoo_AOL.csv", "Yahoo/AOL"),
        ("/Users/tomsather/Downloads/Gmail, Microsoft and Yahoo domains - Microsoft.tsv", "Microsoft"),
    ]
    major_provider_domains = build_major_provider_domains(provider_files)

    entries = load_entries_from_file(args.input_file, args.file_type, args.email_column)
    if not entries:
        print("No entries found in input file. Exiting.")
        return

    output_csv = generate_output_filename(args.input_file)
    unique_domains_path = generate_unique_domains_filename(args.input_file)

    print("==== Spam Trap Detection Engine v2 ====")
    print(f"Input file: {args.input_file}")
    print(f"Rows loaded: {len(entries)}")
    print(f"Config: {config_path}")
    print(f"Suppression domains loaded: {len(suppression_domains)} from {suppression_path}")
    print(f"Major provider domains loaded: {len(major_provider_domains)}")
    print(f"Unique domains output: {unique_domains_path}")
    print(f"Output file: {output_csv}")

    detector = SpamTrapDetector(
        rules=rules,
        suppression_domains=suppression_domains,
        major_provider_domains=major_provider_domains,
        web_check_mode=args.web_check_mode,
        web_check_min_pre_score=args.web_check_min_pre_score,
        web_timeout_override=args.web_timeout,
    )

    start = time.time()
    try:
        asyncio.run(detector.process_entries_async(entries, output_csv, unique_domains_path))
    except KeyboardInterrupt:
        print("Interrupted by user.")
    elapsed = time.time() - start
    print(f"Completed in {elapsed:.2f}s")


if __name__ == "__main__":
    main()
