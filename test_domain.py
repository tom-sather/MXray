import asyncio
from MXray import EmailDomainAnalyzer

async def test():
    analyzer = EmailDomainAnalyzer()
    await analyzer.setup()
    
    print('OHIO:', await analyzer.process_domain_pipeline('ohio.edu'))
    print('AURORA:', await analyzer.process_domain_pipeline('aurorabehavioral.com'))
    
    await analyzer.cleanup()

asyncio.run(test())
