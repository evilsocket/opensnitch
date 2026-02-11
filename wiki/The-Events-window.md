It's the window where you can see all the events that the daemon has registered.

It's divided by tabs, where you can search for events based on the type: nodes, rules, hosts, applications, etc.

The Events tab
---

This is the main log of all the connections that the daemon has intercepted. You can filter connections by action applied, word or limit the number of entries displayed.
You can also sort connections by columns.

![image](https://user-images.githubusercontent.com/2742953/217039798-3477c6c2-d64f-4eea-89af-cd94ee77cff4.png)


**Note:**
When you double click on a row, it will open the detail view of the item clicked.

For example: double click on a Node to open all the connections of that node:

![image](https://user-images.githubusercontent.com/2742953/122284702-24cec100-ceee-11eb-9acb-d7aa8999182b.png)


![image](https://user-images.githubusercontent.com/2742953/122285201-b6d6c980-ceee-11eb-9d7b-b34c16307466.png)

**Note:** The size of the columns is saved when closing the GUI, and restored whe you open it again.


The Rules tab
---

Here you can see all the rules you have defined. Double clicking on a rule will open the details for that view.

You can also perform operations over the rules, one by one or in batch, by right-clicking over a rule:

![image](https://user-images.githubusercontent.com/2742953/122288895-61042080-cef2-11eb-8a90-667800956dda.png)

The rules tab not only lists the application rules, but also the system firewall rules (that is, regular netfilter rules):

<img width="1071" height="551" alt="Captura de pantalla de 2026-02-12 00-39-21" src="https://github.com/user-attachments/assets/3ef47bf9-06ff-476c-9c8f-81d8afe8e2fa" />

Double click on a rule to edit it, or right-click on it to view more options:

<img width="1086" height="651" alt="Captura de pantalla de 2026-02-12 00-41-46" src="https://github.com/user-attachments/assets/0c6d68c3-989a-4791-84c6-57f888ff514a" />


The netstat tab
---

This view lists all the connections of a node. It's similar to `netstat` or `ss`. 

<img width="1100" height="553" alt="Captura de pantalla de 2026-02-12 00-35-34" src="https://github.com/user-attachments/assets/a32ef8eb-5619-448e-bc1d-f4a991732f88" />

Double click on a row to view the details of the item.
