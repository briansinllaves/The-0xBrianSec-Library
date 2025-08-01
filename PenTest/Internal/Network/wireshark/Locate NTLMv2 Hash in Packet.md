### **Pentest Note: Locating NTLMv2 Hash in Packets Using Wireshark**

---

#### **Step 1: Apply the NTLMv2 Filter**

- **Filter:** 
  - Apply the filter `ntlmssp.ntlmv2_response` in Wireshark.
  - **Use Case:** This filter isolates packets containing NTLMv2 responses, making it easier to locate the hash.

---

#### **Step 2: Select and Navigate to NTLMSSP Section**

- **Select a Packet:** 
  - Choose a packet from the filtered results that contains the NTLMv2 response.
  
- **Navigate to NTLMSSP Section:**
  - In the **Packet Details** pane (middle pane), expand the relevant sections:
    - **Hypertext Transfer Protocol (if present)**
    - **Simple and Protected GSS-API Negotiation Protocol (if present)**
    - **Security Support Provider Interface (if present)**
    - **NTLMSSP: NTLMv2 Response**

---

#### **Step 3: Locate the NTLMv2 Hash**

- **Find the NTLMv2 Hash:**
  - Within the **NTLMSSP: NTLMv2 Response** section, locate fields like **NTLMv2 Response** and **Client Challenge**.
  - The **NTLMv2 Response** field contains the NTLMv2 hash.

---

#### **Step 4: Search for the NTLMv2 Hash in Other Packets**

- **Copy the Hash:**
  - Right-click the **NTLMv2 Response** field and select **"Copy" -> "Value"**.
  
- **Search for the Hash in Other Packets:**
  - Go to **Edit -> Find Packet** (or press **Ctrl+F**).
  - In the **Find Packet** window:
    - Select **"By String"**.
    - Paste the copied hash value into the search field.
    - Choose the appropriate search criteria (Packet list, Packet bytes, or Packet details).
  - Click **"Find"** to locate other packets containing this hash.
