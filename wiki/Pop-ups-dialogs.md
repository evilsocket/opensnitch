Whenever a process wants to establish a new connection, OpenSnitch will prompt you to allow or deny it.

![image](https://user-images.githubusercontent.com/2742953/124111463-9b7cca00-da69-11eb-8a15-bf2f61e18f66.png)

Fields meaning:

1. The name of the executable.
2. The command that the user typed.
3. The path to the executable.

Notes:

- If the user typed the absolute path to the binary, then the 3rd field is not displayed.
- If the typed command equals to the name of the binary (like in `curl -L http://..`), the 1st and 2nd executable name will be equal. It seems logical, but in some cases as the one shown in the screen shot, it's not always the case.
- If the text of a field is too large to fit in the window, 3 dots are added to the end of the text (![image](https://user-images.githubusercontent.com/2742953/124112656-cc113380-da6a-11eb-9c04-1f8d61059320.png)
) . Place the cursor over the text to see all the text.

Advanced view
---

By clicking on the [+] button, you can display the _advanced view_, where you can select more connection fields to block:

![image](https://user-images.githubusercontent.com/2742953/124111547-b4857b00-da69-11eb-963b-cf32c6bdc3df.png)
