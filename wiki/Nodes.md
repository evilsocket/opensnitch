A node is a daemon running on a machine. You can install the daemon on multiple machines, and manage them from the server (i.e.:GUI).

![image](https://user-images.githubusercontent.com/2742953/196779014-ff8099bc-9532-4786-9a92-3e30de549cd4.png)

You can view the list of known nodes from the tab Nodes:

![image](https://user-images.githubusercontent.com/2742953/82752021-9d328380-9dbb-11ea-913e-80f7b551a6c7.png)

And by double clicking on a node, you can see the network activity for that node.

#### Configuration

As explained in the [Configurations](https://github.com/evilsocket/opensnitch/wiki/Configurations#gui) section, you have to launch the daemon as follow in order to accept connections from remote nodes:

`$ /usr/local/bin/opensnitch-ui --socket "[::]:50051"`

It'll make the GUI listen on port 50051, any IP.

Now you need to configure each node to connect to the server. In `/etc/opensnitchd/default-config.json` set the Address field to the server address:

```json
    "Server":
    {
        "Address":"192.168.1.100:50051",
    },
```

Once a node is connected, you can also change it from the GUI, without connecting to the node via SSH, etc:

![image](https://user-images.githubusercontent.com/2742953/196782343-bbc28fea-f9a1-4842-a285-e557c6ac5b27.png)

(the field Address refers to the server address where the node will connect to)
