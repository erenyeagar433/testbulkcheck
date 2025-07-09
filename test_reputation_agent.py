from app.utils.reputation import (
    is_ip,
    is_url,
    check_ip_abuseipdb,
    check_virustotal
)

def test_ioc_reputation():
    iocs = [
        "8.8.8.8",                         # valid IP
        "45.33.32.156",                    # another IP
        "https://malicious.test.example", # example URL (will likely 404 in VT)
        "http://example.com"              # common URL
    ]

    for ioc in iocs:
        print(f"\nChecking: {ioc}")

        if is_ip(ioc):
            print("Type: IP")
            abuse_result = check_ip_abuseipdb(ioc)
            vt_result = check_virustotal(ioc)
            print("AbuseIPDB:", abuse_result)
            print("VirusTotal:", vt_result)

        elif is_url(ioc):
            print("Type: URL")
            vt_result = check_virustotal(ioc)
            print("VirusTotal:", vt_result)

        else:
            print("Invalid IOC format")

if __name__ == "__main__":
    test_ioc_reputation()
