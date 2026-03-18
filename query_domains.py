#!/usr/bin/env python3
import aiosqlite
import asyncio
import json
from datetime import datetime

class DomainQueryTool:
    def __init__(self, db_path=".cache/domain_checks.db"):
        self.db_path = db_path

    async def show_basic_stats(self):
        """Show basic statistics about the domain checks"""
        async with aiosqlite.connect(self.db_path) as db:
            print("\n=== Database Statistics ===")
            
            # Count total domains
            async with db.execute("SELECT COUNT(*) FROM domain_checks") as cursor:
                count = await cursor.fetchone()
                print(f"Total domains checked: {count[0]}")
            
            # Count by MX provider
            print("\nMX Provider Distribution:")
            async with db.execute("""
                SELECT mx_category, COUNT(*) as count 
                FROM domain_checks 
                GROUP BY mx_category 
                ORDER BY count DESC
            """) as cursor:
                async for row in cursor:
                    print(f"  {row[0]}: {row[1]}")

            # Count by status
            print("\nStatus Distribution:")
            async with db.execute("""
                SELECT status, COUNT(*) as count 
                FROM results_history 
                GROUP BY status 
                ORDER BY count DESC
            """) as cursor:
                async for row in cursor:
                    print(f"  {row[0]}: {row[1]}")

    async def show_recent_checks(self, limit=5):
        """Show most recently checked domains"""
        async with aiosqlite.connect(self.db_path) as db:
            print(f"\n=== {limit} Most Recent Checks ===")
            async with db.execute("""
                SELECT domain, mx_category, has_mx, has_a, has_spf, has_dmarc, last_checked 
                FROM domain_checks 
                ORDER BY last_checked DESC 
                LIMIT ?
            """, (limit,)) as cursor:
                async for row in cursor:
                    print(f"\nDomain: {row[0]}")
                    print(f"MX Provider: {row[1]}")
                    print(f"Has MX: {'Yes' if row[2] else 'No'}")
                    print(f"Has A: {'Yes' if row[3] else 'No'}")
                    print(f"Has SPF: {'Yes' if row[4] else 'No'}")
                    print(f"Has DMARC: {'Yes' if row[5] else 'No'}")
                    print(f"Last Checked: {row[6]}")
                    print("-" * 40)

    async def search_domains(self, search_term):
        """Search for specific domains"""
        async with aiosqlite.connect(self.db_path) as db:
            print(f"\n=== Search Results for '{search_term}' ===")
            async with db.execute("""
                SELECT d.domain, d.mx_category, r.status, r.reason, d.last_checked
                FROM domain_checks d
                LEFT JOIN results_history r ON d.domain = r.domain
                WHERE d.domain LIKE ?
                ORDER BY d.last_checked DESC
            """, (f"%{search_term}%",)) as cursor:
                async for row in cursor:
                    print(f"\nDomain: {row[0]}")
                    print(f"MX Provider: {row[1]}")
                    print(f"Status: {row[2]}")
                    print(f"Reason: {row[3]}")
                    print(f"Last Checked: {row[4]}")
                    print("-" * 40)

    async def show_provider_domains(self, provider):
        """Show all domains using a specific provider"""
        async with aiosqlite.connect(self.db_path) as db:
            print(f"\n=== Domains using {provider} ===")
            async with db.execute("""
                SELECT domain, mx_records, last_checked
                FROM domain_checks 
                WHERE mx_category = ?
                ORDER BY domain
            """, (provider,)) as cursor:
                async for row in cursor:
                    print(f"\nDomain: {row[0]}")
                    print(f"MX Records: {row[1]}")
                    print(f"Last Checked: {row[2]}")
                    print("-" * 40)

    async def show_mx_records(self, domain=None):
        """Show MX records for a domain or all domains"""
        async with aiosqlite.connect(self.db_path) as db:
            if domain:
                print(f"\n=== MX Records for {domain} ===")
                query = """
                    SELECT domain, mx_records, mx_category, last_checked 
                    FROM domain_checks 
                    WHERE domain = ?
                """
                params = (domain,)
            else:
                print("\n=== All MX Records ===")
                query = """
                    SELECT domain, mx_records, mx_category, last_checked 
                    FROM domain_checks 
                    WHERE has_mx = 1
                    ORDER BY domain
                """
                params = ()

            async with db.execute(query, params) as cursor:
                async for row in cursor:
                    print(f"\nDomain: {row[0]}")
                    mx_records = json.loads(row[1])  # Convert JSON string back to list
                    print(f"MX Records:")
                    for record in mx_records:
                        print(f"  - {record}")
                    print(f"Provider: {row[2]}")
                    print(f"Last Checked: {row[3]}")
                    print("-" * 40)

async def main():
    tool = DomainQueryTool()
    
    while True:
        print("\nDomain Query Tool")
        print("1. Show Basic Statistics")
        print("2. Show Recent Checks")
        print("3. Search Domains")
        print("4. Show Domains by Provider")
        print("5. Show MX Records")
        print("6. Exit")
        
        choice = input("\nEnter your choice (1-6): ")
        
        if choice == "1":
            await tool.show_basic_stats()
        elif choice == "2":
            limit = int(input("How many recent checks to show? "))
            await tool.show_recent_checks(limit)
        elif choice == "3":
            search_term = input("Enter domain search term: ")
            await tool.search_domains(search_term)
        elif choice == "4":
            provider = input("Enter provider name (Google, Microsoft, etc): ")
            await tool.show_provider_domains(provider)
        elif choice == "5":
            domain = input("Enter domain (or press Enter for all): ").strip()
            await tool.show_mx_records(domain if domain else None)
        elif choice == "6":
            print("Goodbye!")
            break
        else:
            print("Invalid choice, please try again")
        
        input("\nPress Enter to continue...")

if __name__ == "__main__":
    asyncio.run(main()) 