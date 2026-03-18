import asyncio
import dns.asyncresolver

PUBLIC_RESOLVERS = [
    '8.8.8.8', '8.8.4.4',
    '1.1.1.1', '1.0.0.1',
    '9.9.9.9', '149.112.112.112'
]

async def check():
    resolver = dns.asyncresolver.Resolver(configure=False)
    resolver.nameservers = PUBLIC_RESOLVERS
    resolver.timeout = 5
    resolver.lifetime = 5
    try:
        ans = await resolver.resolve('ahsys.org', 'MX')
        print("MX:", [str(r.exchange) for r in ans])
    except Exception as e:
        print("MX Error:", type(e), e)
    
    try:
        ans = await resolver.resolve('ahsys.org', 'A')
        print("A:", [str(r.address) for r in ans])
    except Exception as e:
        print("A Error:", type(e), e)

asyncio.run(check())
