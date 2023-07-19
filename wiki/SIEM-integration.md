Integration with SIEM systems (>= v1.6.0)
---

You can configure OpenSnitch to send intercepted events to third-party SIEM solutions.

**Firstly, configure a logger (only syslog is supported as of v1.6.0):**

/etc/opensnitch/default-config.json

```json
    "Server": {
        "Address": "unix:///tmp/osui.sock",
        "LogFile": "/var/log/opensnitchd.log",
        "Loggers": [
            {
                "Name": "syslog",
                "Server": "127.0.0.1:514",
                "Protocol": "udp",
                "Format": "rfc5424",
                "Tag": "opensnitchd"
            }
        ]
    },
    (...)
```

syslog logger possible fields and values:

|Option|Description|
|-------|-------|
|Name|Name that identifies the logger: syslog|
|Server|Server address. Leave it empty to log events to the local daemon|
|Protocol|Only applicable if Server is not empty|
|Format|possible values: rfc5424,csv . RFC5424 will log events witht the format KEY=VALUE|
|Tag|Optional tag to identify events in the syslog. If empty, syslog will use the name of the daemon|

After modify the configuration, restart OpenSnitch.

Now you should see the events on your SIEM, for example:

![image](https://user-images.githubusercontent.com/2742953/167249501-163fa985-f186-415f-93b6-c86cab2fe0b3.png)

![image](https://user-images.githubusercontent.com/2742953/167288109-4f791761-e826-4619-b042-e3a580782e79.png)



Howto configure OpenSnitch with Grafana+Loki+promtail+syslog-ng
---


1. Unzip this file [opensnitch-grafana-siem.zip](https://github.com/evilsocket/opensnitch/files/8716183/opensnitch-grafana-siem.zip)

   The setup is based on the following example, so all the commands to set it up applies:
   https://github.com/grafana/loki/tree/main/examples/getting-started
   
   Docs: https://grafana.com/docs/loki/latest/getting-started/

2. Enter into the directory where the `docker-compose.yaml` is and execute:
   ```bash
   # docker-compose up -d
   siem_minio_1 done
   siem_write_1 done
   siem_read_1 done
   siem_gateway_1 done
   siem_grafana_1 done
   siem_promtail_1 done
   syslog-ng done

   ```
   
3. Add logger configuration as explained above to send events to 127.0.0.1 on port 514:
```json
    "Server": {
        (...)
        "Loggers": [
            {
                "Name": "syslog",
                "Server": "127.0.0.1:514",
                "Protocol": "udp",
                "Format": "rfc5424",
                "Tag": "opensnitchd"
            }
        ]
    },
```

4. Restart opensnitch: `# service opensnitch restart`
5. Execute `docker ps` and verify that nginx, grafana, promtail, syslog-ng and loki are running.
6. Open a web browser and open `127.0.0.1:3000` . Login with admin:admin
7. Go to Configuration -> Data Sources -> click on Test, and verify that the `Data source is connected and labels found`
8. Go to Explore -> select Loki in the combo box and expand the "Log browser" dropdown box. There should be a label named "opensnitch"
9. Click on it, and execute the query to list the events collected.


The zip file contains a `dashboard.json`. Hover the mouse over the `+` icon, click on Import and paste the content of the file.

Then you can open the dashboard and monitorized the events.





Howto configure OpenSnitch with ElasticSearch + LogStash + Kibana
---


1. Unzip this file [opensnitch-elasticstack-siem.zip](https://github.com/evilsocket/opensnitch/files/12095966/opensnitch-elasticstack-siem.zip)

   The setup is based on the following example, so all the commands to set it up applies:
   [https://github.com/grafana/loki/tree/main/examples/getting-started](https://github.com/yangjunsss/docker-elk-syslog)

   Note: The example is modified to use versions 8.7.1 instead of 5.4. To review the changes execute from that directory `git diff .`

   Docs:
   https://www.elastic.co/guide/en/logstash/current/plugins-inputs-tcp.html
   https://www.elastic.co/guide/en/logstash/current/plugins-inputs-udp.html

1. Enter into the directory where the `docker-compose.yml` is and execute:
   ```bash
   # docker-compose up -d
   Recreating docker-elk-elasticsearch_logstash_1 ... 
   Recreating docker-elk-elasticsearch_logstash_1 ... done
   Recreating docker-elk-syslog_logstash_1 ... 
   Recreating docker-elk-syslog_logstash_1 ... done
   Recreating docker-elk-kibana_logstash_1 ... 
   Recreating docker-elk-kibana_logstash_1 ... done
   ```
   
2. Add the logger configuration as explained above to send events to 127.0.0.1 on port 3333:
```json
    "Server": {
        (...)
        "Loggers": [
            {
                "Name": "remote",
                "Server": "127.0.0.1:3333",
                "Protocol": "tcp",
                "Format": "json",
                "Tag": "opensnitchd"
            }
        ]
    },
```

4. Restart opensnitch: `# service opensnitch restart`
5. Execute `docker ps` and verify that elasticsearch, logstash and kibana are running.

    If everything went fine, LogStash should be receiving events like this one:
       ```
        {
        "@timestamp" => 2023-07-19T13:49:54.546806822Z,
          "document" => {
              "Type" => 0,
              "Rule" => "000-allow-domains",
            "Action" => "allow",
             "Event" => {
                    "protocol" => "udp",
                      "dst_ip" => "9.9.9.9",
                "process_args" => [
                    [0] "/usr/bin/firefox-esr"
                ],
        (...)
        }
       ```
   
7. Open a web browser and head to `127.0.0.1:5601`.
8. Click on the left Menu -> Analytics -> Discover to view collected events:

![image](https://github.com/evilsocket/opensnitch/assets/2742953/48fbc1ab-a30c-4adf-95ff-b918288dce8d)


9. To create a dashboard to visualize the data, go to Analytics -> Dashboard -> Create dasboard

![image](https://github.com/evilsocket/opensnitch/assets/2742953/9c5a8bfc-98e5-406b-81fd-b6ac7b22e866)


### Troubleshooting Elastic stack

 - Verify that the TCP port 3333 is open:

   ```bash
   ~ $ ss -lptn | grep 3333
    LISTEN 0      1024   [::ffff:127.0.0.1]:3333             *:*    users:(("java",pid=3625239,fd=107))
   ```

   You should be able to connect: `~ $ telnet 127.0.0.1 3333`

 - If it's not open, analyze LogStash container logs: `~ $ docker logs -f -n 100 ec4e3b0t7d87`

   There should be a log line like this one:
   `[2023-07-19T13:40:11,945][INFO ][logstash.inputs.tcp      ][main][cbc1d83a3460288f8b2c2a0399fe2b85eab0199a0a58318f75a4f931f9175f9e] Starting tcp input listener {:address=>"127.0.0.1:3333", :ssl_enable=>false}`


 - If you cannot connect, disable opensnitch's System firewall from the GUI, or set Enable to false in /etc/opensnitchd/system-fw.json and try again.
