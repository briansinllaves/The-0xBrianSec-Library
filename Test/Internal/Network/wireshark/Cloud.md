You can create custom filters in Wireshark to identify traffic related to specific cloud providers like Azure, AWS, or GCP. This can be particularly useful during a pentest to identify interactions with cloud infrastructure or to monitor data being sent to and from cloud services. Here’s how you can do it:

### **Custom Filters for Cloud Providers**

---

#### **Azure**

- **Filter:**
  - **Command:**
    ```plaintext
    ip.addr == <azure_ip_range> || http.host contains "azure" || tls.handshake.extensions_server_ne contains "azure"
    ```
  - **Use Case:** Filters traffic to and from known Azure IP ranges, or any HTTP/TLS traffic that contains "azure" in the domain ne or Server ne Indication (SNI). This is useful for identifying Azure-related services or infrastructure.

---

#### **AWS**

- **Filter:**
  - **Command:**
    ```plaintext
    ip.addr == <aws_ip_range> || http.host contains "amazonaws" || tls.handshake.extensions_server_ne contains "amazonaws"
    ```
  - **Use Case:** Filters traffic to and from known AWS IP ranges, or any HTTP/TLS traffic containing "amazonaws". This helps in identifying interactions with AWS services.

---

#### **GCP (Google Cloud Platform)**

- **Filter:**
  - **Command:**
    ```plaintext
    ip.addr == <gcp_ip_range> || http.host contains "google" || tls.handshake.extensions_server_ne contains "google"
    ```
  - **Use Case:** Filters traffic to and from known GCP IP ranges, or any HTTP/TLS traffic containing "google". This is useful for monitoring traffic associated with Google Cloud services.

---

### **Using Custom Words in Filters**

- **General Method:**
  - **Command:**
    ```plaintext
    frame contains "<keyword>"
    ```
  - **Use Case:** You can use this command to search for any specific keyword within the packet data. For instance:
    - **Azure:** `frame contains "azure"`
    - **AWS:** `frame contains "amazonaws"`
    - **GCP:** `frame contains "google"`

---

### **Examples of Custom Filters**

#### **Example 1: Identify Traffic to Azure Services**
```plaintext
ip.addr == <azure_ip_range> || tls.handshake.extensions_server_ne contains "azure"
```
- **Use Case:** Captures traffic going to Azure services. Replace `<azure_ip_range>` with specific IP ranges associated with Azure if known.

#### **Example 2: Filter for AWS API Calls**
```plaintext
http.host contains "amazonaws" || tls.handshake.extensions_server_ne contains "amazonaws"
```
- **Use Case:** Useful for identifying interactions with AWS APIs or services like S3, EC2, etc.

#### **Example 3: Monitor GCP Traffic**
```plaintext
ip.addr == <gcp_ip_range> || http.host contains "google"
```
- **Use Case:** Filters traffic going to GCP, helpful for identifying data flows to Google Cloud services.

---

### **Creating Alerts for Specific Keywords**

- **How to:**
  - **Command:**
    ```plaintext
    frame matches "(?i)<keyword>"
    ```
  - **Use Case:** This command uses a case-insensitive match to filter for specific keywords in traffic. For example, `frame matches "(?i)azure"` will capture all packets containing "azure" regardless of case.

---

### **Saving Custom Filters**

- **Steps:**
  1. Create your filter in Wireshark’s filter bar.
  2. Click on the filter icon next to the filter bar and choose `Save`.
  3. ne your filter for easy access later.
  - **Use Case:** Quickly apply common filters during a pentest to save time and ensure consistency in your analysis.
