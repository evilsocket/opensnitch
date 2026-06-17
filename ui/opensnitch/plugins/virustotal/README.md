## VirusTotal plugin

This is a simple plugin that analyzes new outbound connections with virustotal:

<img width="562" height="342" alt="9-vt-1" src="https://github.com/user-attachments/assets/f048e1cd-4a25-4dd3-a43d-717ff0f0cbd3" />


<br>It also obtains information about domains in the Hosts tab:

<img width="825" height="236" alt="hosts-vt" src="https://github.com/user-attachments/assets/c15dd689-ace5-4df6-958e-19dc27a4c933" />


<br>and adds a tab to the process dialog, which obtains information about the process if the hash was submitted to virustotal.

<img width="736" height="484" alt="8-vt-1" src="https://github.com/user-attachments/assets/1368e823-b8ff-4671-aecf-5365f742deab" />


<br>**Privacy warning:** remember that the domains, IPs or hashes will be sent to the servers of virustotal.

## Prerequisites

Get an API key: https://virustotal.readme.io/docs/please-give-me-an-api-key

## Configuration

Firstly add a new rule to allow connections from the GUI to www.virustotal.com:

```json
{
    "created": "2023-02-19T20:44:36.000000Z",
    "name": "allow-virustotal",
    "enabled": true,
    "action": "allow",
    "duration": "always",
    "operator": {
        "type": "list",
        "operand": "list",
        "list": [
            {
                "type": "simple",
                "operand": "dest.port",
                "data": "443"
            },
            {
                "type": "simple",
                "operand": "dest.host",
                "data": "www.virustotal.com"
            }
        ]
    }
}
```

Secondly, create the plugin configuration under `/home/<your-user>/.config/opensnitch/actions/virustotal.json`:

```json
{
  "name": "virustotal",
  "created": "",
  "updated": "",
  "description": "analyze connections properties with virustotal",
  "type": ["popups", "proc-dialog", "main-dialog"],
  "actions": {
      "virustotal": {
          "enabled": true,
          "loglevel": "debug",
          "config": {
              "api_timeout": 2,
              "api_quota": 500,
              "api_key": "<your-api-key>",
              "api_domains_url": "https://www.virustotal.com/api/v3/domains/",
              "api_ips_url": "https://www.virustotal.com/api/v3/ip_addresses/",
              "api_files_url": "https://www.virustotal.com/api/v3/files/"
          },
          "check": ["ips", "domains", "hashes"],
          "malicious": {
              "minimum-threshold": 1,
              "action": "reject",
              "icon": "dialog-warning",
              "use-community-score": true,
              "use-reputation": true,
              "use-suspicious": true
          },
          "widgets-colors": {
              "malicious": "red",
              "benign": "green",
              "unknown": "darkOrange"
          },
          "exclusions": {
              "ips": ["127.", "192.168."],
              "domains": [".lan"]
          }
      }
  }
}
```

|item|value|
|----|-----|
|config.api_timeout|maximum allowed time in seconds to obtain a response from the server. 1 is usually too low. 2 or 3 usually works fine.|
|config.api_quota| Maximum allowed requests. If we exceed this value, we won't try to analyze new connections (they'll be denied anyway). The free account has a limit of 500. If you use a different license, adjust this value accordingly.|
|malicious.icon|Change the icon of the popup if the connection is flagged as malicious. Leave empty to skip it. The name of the icon depends on the icon theme of your Desktop Environment|
|malicious.minimum-threshold|The minimum malicious score used to consider an outbound connection potentially malicious.|
|malicious.use-community-score|Users can vote to flag something as malicious or not (IP, domain, hash, etc).|
|malicious.use-reputation||
|exclusions.ips|IPs to exclude from being analyzed. By default private IPs are already excluded. The exclusion will take effect if the IP contains the exclusion|
|exclusions.domains|Domains to exclude from being analyzed. The exclusion will take effect if the domain contains the exclusion (for example: www.github.com.lan)|

#### API Documentation:                                                              

      - https://developers.virustotal.com/reference/domain-info
      - https://developers.virustotal.com/reference/domains-1
      - https://developers.virustotal.com/reference/ip-info
      - https://docs.virustotal.com/reference/ip-object
      - https://developers.virustotal.com/reference/file-info
      - https://docs.virustotal.com/reference/files
