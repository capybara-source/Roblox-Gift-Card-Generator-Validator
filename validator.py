import asyncio
import aiohttp
import time
import random

# Settings
CONCURRENT_REQUESTS = 5  # Number of concurrent requests
MAX_RETRIES = 3          # Retry attempts for server errors
DELAY_BETWEEN_REQUESTS = (0.2, 0.5)  # Random delay in seconds between requests

REDEEM_URL = "https://www.roblox.com/redeem"

# Replace with your actual .ROBLOSECURITY cookie
ROBLOSECURITY_COOKIE = "YOUR_COOKIE_HERE"

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "Content-Type": "application/json",
}

async def get_csrf_token(session):
    """Get a fresh CSRF token from Roblox."""
    try:
        async with session.post("https://auth.roblox.com/v2/logout", headers=HEADERS) as r:
            token = r.headers.get("x-csrf-token")
            return token
    except Exception as e:
        print(f"[!] Error getting CSRF token: {e}")
        return None

async def validate_code(session, code, csrf_token):
    retries = 0
    while retries < MAX_RETRIES:
        try:
            url = REDEEM_URL.format(code=code)
            async with session.post(url, headers={**HEADERS, "X-CSRF-TOKEN": csrf_token}) as response:
                text = await response.text()
                
                # Refresh CSRF token if Roblox rejects it
                if response.status == 403 and 'x-csrf-token' in response.headers:
                    csrf_token = response.headers['x-csrf-token']
                    retries += 1
                    print(f"[!] CSRF token expired for {code}, refreshing... Retry {retries}")
                    continue
                
                if response.status == 200:
                    if "success" in text.lower():
                        print(f"[+] VALID CODE: {code}")
                        with open("valid.txt", "a") as vf:
                            vf.write(code + "\n")
                    else:
                        print(f"[-] Invalid: {code}")
                    return
                elif response.status == 500:
                    retries += 1
                    print(f"[!] Server error 500 for {code}. Retrying ({retries}/{MAX_RETRIES})...")
                    await asyncio.sleep(1)
                else:
                    print(f"[-] Invalid: {code} (status {response.status})")
                    return

        except Exception as e:
            print(f"[!] Error validating {code}: {e}")
            return

    print(f"[!] Failed to redeem {code} after {MAX_RETRIES} retries")

    # Small random delay between requests to reduce server stress
    await asyncio.sleep(random.uniform(*DELAY_BETWEEN_REQUESTS))

async def run_validator(codes):
    connector = aiohttp.TCPConnector(limit=CONCURRENT_REQUESTS, ssl=False)
    cookies = {".ROBLOSECURITY": ROBLOSECURITY_COOKIE}
    
    async with aiohttp.ClientSession(connector=connector, cookies=cookies) as session:
        csrf_token = await get_csrf_token(session)
        if not csrf_token:
            print("[!] Failed to get CSRF token. Exiting.")
            return
        tasks = [validate_code(session, code.strip(), csrf_token) for code in codes]
        await asyncio.gather(*tasks)

def main():
    try:
        with open("roblox.txt", "r") as f:
            codes = f.readlines()
    except FileNotFoundError:
        print("[!] 'roblox.txt' not found. Please create it with one code per line.")
        return

    start = time.perf_counter()
    asyncio.run(run_validator(codes))
    end = time.perf_counter()
    print(f"\nDone. Checked {len(codes)} codes in {end - start:.2f} seconds.")

if __name__ == "__main__":
    main()
