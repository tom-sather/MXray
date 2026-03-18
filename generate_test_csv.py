import csv
import random

domains = [
    "gmail.com", "yahoo.com", "outlook.com", "ahsys.org",
    "hubblehost.com", "google.com", "microsoft.com", "apple.com",
    "invalid-domain-does-not-exist.com", "mailinator.com"
]

with open('test_dummy.csv', 'w', newline='') as f:
    writer = csv.writer(f)
    writer.writerow(["email", "id", "name"])
    for i in range(150000): # large enough to trigger chunking (chunk size 50k)
        domain = random.choice(domains)
        email = f"user{i}@{domain}"
        writer.writerow([email, i, f"User {i}"])
print("Created test_dummy.csv with 150000 rows")
