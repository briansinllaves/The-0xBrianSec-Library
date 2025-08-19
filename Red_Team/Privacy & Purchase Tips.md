# Privacy & Purchase Tips

| Item   | How                                                                 |
|--------|---------------------------------------------------------------------|
| Azure  | New account + pay with Privacy.com/Revolut virtual card             |
| Domain | Buy via AWS/Azure, enable WHOIS Privacy                             |
| VPN    | Use NordVPN locally before SSH to hide real IP from logs            |
| Tips   | Use separate aliases for every service; never mix with personal     |
| Logs   | Send service logs to a remote syslog server outside the lab         |

---

**Additional Notes:**
- Always use burner email addresses and phone numbers for registration.
- Prefer cloud providers that accept crypto or prepaid cards for added anonymity.
- Avoid reusing passwords or usernames across services.
- Routinely audit and rotate credentials and payment methods.
- Consider using disposable VMs or containers for purchases and management.
- Never access sensitive infrastructure from your personal network or device.

---

## Anonymous SIM Card Acquisition & Setup (Red Team Walkthrough)

1. **Preparation**
    - Use a privacy-focused browser (e.g., Tor Browser) and a VPN (NordVPN, Mullvad, etc.).
    - Never use your real IP or personal device for research or purchases.
    - Consider using a dedicated, clean laptop or VM for all operational purchases and SIM management.

2. **Purchase a SIM Card Anonymously**
    - Find online retailers or local stores that sell prepaid SIM cards for cash.
    - For online: Use Tor to access privacy-friendly marketplaces (look for vendors accepting Monero/XMR or Bitcoin).
    - Pay with Monero (XMR), Bitcoin, or a Privacy.com/virtual prepaid card.
    - Ship to a drop address, PO box, or use a package forwarding service that doesn’t require real ID.
    - If buying in person, pay cash and avoid locations with heavy surveillance or loyalty programs.

3. **Burner Phone Selection & Setup**
    - Purchase a basic, unlocked GSM phone (2G/3G/4G "feature phone" or cheap Android) with cash at a physical store.
    - Avoid smartphones with Wi-Fi, Bluetooth, or GPS if possible; if using a smartphone, disable all radios except cellular.
    - Never use your personal phone or any device previously associated with your identity.
    - Remove or cover device identifiers (IMEI stickers, etc.) before use.
    - If possible, use a Faraday bag to transport the phone/SIM until ready for operational use.

4. **Activate the SIM Card**
    - Insert the SIM into the burner phone.
    - If activation requires an ID, use a country/jurisdiction that allows anonymous activation (many EU/US prepaid SIMs do not require ID, but check local laws).
    - If required, use a fake name or a trusted third-party activation service found on privacy forums.
    - Power on the phone only in locations not associated with your real identity (avoid home, work, or known locations).
    - Do not connect the phone to Wi-Fi or pair with any personal devices.

5. **Operational Security**
    - Use the SIM only for red team operations (e.g., SMS-based MFA, account registration, or C2 fallback).
    - Never use the SIM for voice calls or SMS with personal contacts.
    - Rotate SIMs regularly and dispose of them securely after use (destroy SIM and phone if needed).
    - Power on the phone only when needed; keep it powered off and battery removed when not in use.
    - Avoid patterns of use that could be correlated to your real-world activity or locations.
    - Never store sensitive data or credentials on the device.

6. **Ongoing Use**
    - Top up using anonymous payment methods (crypto, prepaid cards, or cash at retail).
    - Use the SIM in conjunction with a VPN and Tor for all communications (e.g., for tethering or mobile data).
    - Never access sensitive infrastructure from a network associated with your real identity.
    - Consider swapping IMEI/phone hardware if using the SIM for extended periods.

---

**Example Workflow for a Red Teamer:**

1. Connect to NordVPN or Mullvad, then launch Tor Browser.
2. Locate a privacy-friendly SIM card vendor (preferably one accepting Monero).
3. Purchase a prepaid SIM card using Monero or a Privacy.com card.
4. Ship to a non-attributable address (drop, PO box, forwarding service).
5. Buy a burner phone with cash at a local store (avoid using your regular phone).
6. Receive the SIM and insert it into the burner phone.
7. Activate the SIM (using anonymous details if required), in a location not tied to your identity.
8. Use the SIM for red team registrations, SMS verifications, or C2 fallback.
9. Top up with crypto or cash as needed.
10. When finished, destroy the SIM and burner device or store securely for future use.

---

**Tips for Maximum Cell Phone OpSec:**
- Never power on the phone at home, work, or any location associated with you.
- Never insert the SIM into a device that has ever been linked to your real identity.
- Use the phone only for operational tasks; never for personal browsing, calls, or apps.
- Remove the battery when not in use, or store in a Faraday bag.
- If possible, randomize locations and times of use to avoid pattern analysis.
- Consider using multiple SIMs/phones for different operations and rotating them regularly.
- Destroy or securely dispose of all hardware and packaging after use.

---

**Tip:**  
Never mix operational SIMs, emails, or payment methods with your personal life. Treat every asset as disposable and compartmentalized.

