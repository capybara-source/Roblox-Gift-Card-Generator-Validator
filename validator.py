import asyncio
import aiohttp
import time
import random
import os
from datetime import datetime

# Settings
CONCURRENT_REQUESTS = 5  # Adjust if you're using proxies or hitting rate limits
MAX_RETRIES = 3          # Retry attempts for server errors
DELAY_BETWEEN_REQUESTS = (0.2, 0.5)  # Random delay in seconds between requests

# The URL for the redemption page
REDEEM_URL = "https://www.roblox.com/redeem"

# Replace with your actual .ROBLOSECURITY cookie
ROBLOSECURITY_COOKIE = "YOUR_COOKIE_HERE"

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "Content-Type": "application/x-www-form-urlencoded",
}

async def get_csrf_token(session):
    """Get a fresh CSRF token from Roblox."""
    try:
        async with session.get("https://www.roblox.com/redeem", headers=HEADERS) as r:
            # Extract the CSRF token from the page's cookies or response headers
            csrf_token = r.cookies.get(".ROBLOSECURITY", "").get("X-CSRF-TOKEN")
            return csrf_token
    except Exception as e:
        print(f"[!] Error getting CSRF token: {e}")
        return None

async def validate_code(session, code, csrf_token):
    retries = 0
    while retries < MAX_RETRIES:
        try:
            data = {
                "code": code,
                "csrf_token": csrf_token,  # Ensure CSRF token is sent in the body
            }
            async with session.post(REDEEM_URL, data=data, headers={**HEADERS, "X-CSRF-TOKEN": csrf_token}) as response:
                text = await response.text()

                # Debugging: Log the response body to understand why it's failing
                print(f"[DEBUG] Response for {code}: {text}")

                if response.status == 200:
                    if "successfully redeemed" in text.lower():
                        print(f"[+] VALID CODE: {code}")
                        if not os.path.exists("valid.txt"):
                            with open("valid.txt", "w") as vf:
                                vf.write("")
                        with open("valid.txt", "a") as vf:
                            vf.write(f"{code} | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    else:
                        print(f"[-] Invalid: {code} (Unable to redeem or expired)")
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
