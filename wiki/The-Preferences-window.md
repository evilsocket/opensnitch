Here you can configure the settings of the GUI and the nodes.

Some things to keep in mind:
 - The GUI is a server, which receives connections from remote nodes.
   That's why there's a section for the UI and the Server.
 - Almost all the labels and widgets have tooltips with explanations of the option.


Pop-ups
---

Default options of the pop-ups

<img width="803" height="551" alt="Captura de pantalla de 2026-02-11 23-58-49999" src="https://github.com/user-attachments/assets/0e740d96-cc66-47d5-bb81-3ad49f1260e7" />

UI
---

Options to customize the UI.

<img width="797" height="544" alt="Captura de pantalla de 2026-02-12 00-51-26" src="https://github.com/user-attachments/assets/501d2fd1-98dc-480f-9f4b-4f1a095d3793" />

 - Refresh interval: controls how often the view is refreshed. Default 0.
   If there're multiple nodes, or a lot of events, a value greater than 0 will help to redouce the CPU usage of the GUI.
 - Theme: The GUI can be customized if you install the package `qt-material` (`$ pip3 install qt-material`)

#### Desktopn notifications

When a pop-up is not answered on time, it'll apply a rule with the default options configured.

It'll also send a notification to the system. Here you can configure the content of that notification:

<img width="652" height="196" alt="Captura de pantalla de 2026-02-12 01-10-18" src="https://github.com/user-attachments/assets/ffd2bd37-ea61-4ffa-b446-b5a4ff75ed46" />

Available fields (use the format `%<field>%`):
 - conn.time, conn.action, conn.dstip, conn.dsthost, conn.dstport, conn.proto, conn.process, conn.process_args, conn.process_cwd, rule.action, rule.name, node.name, node.hostname

Server
---

These options controls the server part of the GUI to deal with nodes.

<img width="798" height="546" alt="Captura de pantalla de 2026-02-12 00-51-41" src="https://github.com/user-attachments/assets/36fd951b-8127-4471-8fb8-984bffb2a42f" />

 - Max server workers:
   Each connected node consumes around 2 workers. If there're more nodes than workers, the GUI won't allow new messages from nodes.
   Increase it if there're more than ~15 nodes connected.
 - Max server clients:
   Limits the number of nodes that can connect to the GUI. 0 unlimited (default).
 - Keepalive interval (milliseconds):
   Every n milliseconds, the server (GUI) verifies if the nodes are alived.
   If it doesn't receive a response from a node in n milliseconds, the `Keepalive timeout` will start to count.
 - Keepalive timeout (milliseconds):
   After n milliseconds, the server (GUI) will close the connection with the node that stopped responding.
   The node if is alived, will try to reconnect.

Nodes
---

Nodes configuration:

<img width="798" height="543" alt="Captura de pantalla de 2026-02-12 00-51-55" src="https://github.com/user-attachments/assets/833e9e98-0f61-40cb-bb36-ff4b7673d427" />

When changing the configuration of a node, be sure that you selected correctly the node!

You can also apply the configuration to all nodes.

More information about nodes management: [Nodes](../wiki/Nodes)

Database
---

<img width="798" height="543" alt="Captura de pantalla de 2026-02-12 00-52-03" src="https://github.com/user-attachments/assets/04d41658-d1c0-4f7c-92e6-2f17de58179d" />


