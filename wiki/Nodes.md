A node is a daemon running on a machine. You can install the daemon on multiple machines, and manage them from the server (i.e.:GUI).
The GUI or TUI acts as the server.

> ℹ️ Note: if you want to install **only** the daemon from the Debian repositories, you'll have to execute this command:
>
> `$ sudo apt install --no-install-recommends opensnitch` (otherwise it'll install both, the daemon and the GUI)

<p align="center">
<img src="https://user-images.githubusercontent.com/2742953/197076010-2502855a-cdae-4f03-90bc-7a715efbbf64.png"/>
</p>

You can view the list of connected nodes from the Nodes tab:

<img width="1074" height="470" src="https://github.com/user-attachments/assets/49199d84-a554-4775-b4fc-0b9e618feb25" />

----

And by double clicking on a node, you can see the network activity of that node.

<img width="1166" height="429" src="https://github.com/user-attachments/assets/2e83f239-d2ef-45e3-9148-babbed7e74e9" />


### Configuration

By default, the GUI (server) and the nodes listen on a unix socket. If you want to manage multiple nodes, you have to change the GUI (server) address from the Preferences -> UI tab.

First change the (server) address of the node from the Preferences dialog, Nodes tab:

<img width="646" height="591" src="https://github.com/user-attachments/assets/e1d8666b-5487-4e78-bb86-f662f8427da3" />

<p>The node will disconnect and try to reconnect to the new address.</p>

<p>Then change the address of the GUI (server):</p>

<img width="646" height="591" src="https://github.com/user-attachments/assets/072f63aa-369e-40e6-bf3f-99395d931018" />

<p></p>
<p></p>

> ⚠️ Important: Before changing the GUI (server) address, always change the node address. Otherwise you'll have to edit the daemon configuration manually.
>



<p></p>
<p>You can also launch the GUI from the terminal like this:</p>

`$ /usr/local/bin/opensnitch-ui --socket "[::]:50051"`

It'll make the GUI listen on port 50051, any IP. You can also use an IP: `$ /usr/local/bin/opensnitch-ui --socket "127.0.0.1:50051"`

--

### Rules configuration

<p>The GUI also allows to configure nodes' rules, both application and system firewall rules.</p>

<p>When there's more than one node connected to the GUI, every dialog of the GUI will display the list of nodes:</p>

<p>Rule</p>
<p></p><img width="560" height="549" src="https://github.com/user-attachments/assets/9ef76be1-2fe0-468d-b6bb-733e60503daa" /></p>

<p>System firewall rule</p>
<p><img width="510" height="353" src="https://github.com/user-attachments/assets/a111b024-424b-4873-97f0-45a3c485cb5b" /></p>


<p>Use the Rules tab to view and monitor the rules of all nodes:</p>
<p><img width="1170" height="472" src="https://github.com/user-attachments/assets/c9320c41-dba8-4667-9e20-d37ef7f5ba7a" /></p>

<p>and apply actions in batch (delete, apply, .. rules)</p>

<p><img width="839" height="529" src="https://github.com/user-attachments/assets/7473531b-09d7-4784-a411-a85d8e639c60" /></p>
