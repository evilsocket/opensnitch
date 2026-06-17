## Highlight plugin

A plugin to colorize rows or cells of the GUI based on patterns.

<img width="935" height="449" alt="Captura de pantalla de 2026-06-17 12-47-22" src="https://github.com/user-attachments/assets/bfbe68d4-1f64-4a31-9cb7-ee43b6b0ec3d" />

<br>There're 4 built-in configurations, used to highlight parts of the GUI, like colorizing actions applied on connections (deny: red, allow: green) or the state of the rules (Enabled: green, Disabled: red):

 - commonDelegateConfig - Events view
 - defaultFWDelegateConfig - System firewall rules view
 - defaultRulesDelegateConfig - Application rules view
 - netstatDelegateConfig - Netstat view

<br>These configurations are defined here: https://github.com/evilsocket/opensnitch/tree/master/ui/opensnitch/actions/default_actions.py

In order to customize the default configurations, copy the json to `/home/<user>/.config/opensnitch/actions/<name>.json` and add your customizations.

**Important:** Don't change the name field (`"name": "commonDelegateConfig",`).

In this example we'll colorize connections blocked by the rule `block-domains` in purple, and connections to the port 443 in darkRed:

```json
        {
          "text": [
            "443"
          ],
          "cols": [7],
          "color": "white",
          "bgcolor": "darkRed",
          "alignment": []
        },
        {
          "text": [
            "block-domains"
          ],
          "cols": [13],
          "color": "white",
          "bgcolor": "darkMagenta",
          "alignment": []
        }
```

<details>
  <summary>Example: commonActionsDelegate.json</summary>

```json
{
  "name": "commonDelegateConfig",
  "created": "",
  "updated": "",
  "description": "customize Events tab view colors. The name of this action MUST be commonDelegateConfig for now",
  "actions": {
    "Highlight": {
      "enabled": true,
      "cells": [
        {
          "text": [
            "allow",
            "✓ online",
            "LISTEN"
          ],
          "cols": [1, 2, 3],
          "color": "green",
          "bgcolor": "",
          "alignment": [
            "center"
          ]
        },
        {
          "text": [
              "drop",
            "deny",
            "☓ offline"
          ],
          "cols": [1, 2, 3],
          "color": "red",
          "bgcolor": "",
          "alignment": [
            "center"
          ]
        },
        {
          "text": [
            "reject"
          ],
          "cols": [1, 2, 3],
          "color": "purple",
          "bgcolor": "",
          "alignment": [
            "center"
          ]
        },
        {
          "text": [
            "Established"
          ],
          "cols": [1],
          "color": "blue",
          "bgcolor": "",
          "alignment": [
            "center"
          ]
        }
      ],
      "rows": [
        {
          "text": [
            "443"
          ],
          "cols": [7],
          "color": "white",
          "bgcolor": "darkRed",
          "alignment": []
        },
        {
          "text": [
            "block-domains"
          ],
          "cols": [13],
          "color": "white",
          "bgcolor": "darkMagenta",
          "alignment": []
        }
      ]
    }
  }
}
```
</details>

## Configuration

Format:
    
```json
    "highlight": {
      "cells": [
        {
          "text": ["allow", "True"],
          "cols": [3, 4],
          "color": "green",
          "bgcolor": "",
          "alignment": ["center"]
        }
      ]
      "rows":[
        {
          "text": ["False"],
          "cols": [3],
          "color": "black",
          "bgcolor": "darkgray"
        }
      ]
    }
```

    cells: rules will be applied only on individual cells.\
    rows: rules will be applied to rows on the given columns.

    Fields:
      text: will match any of the given texts (the comparison is an OR operation).
      cols: look for patterns on these columns. The columns start at 0.
      color: colorizes the color of the text.
      bgcolor: colorizes the background color of the cell.
      alignment: cell's text alignment (values: hcenter, vcenter, center).

    Color names: https://doc.qt.io/qt-6/qcolor.html#predefined-colors

    Notes:
     - There're 3 default configurations that are applied on the views:
         commonDelegateConfig, defaultRulesDelegateConfig and
         defaultFWDelegateConfig

        Creating/Copying these configurations under
        XDG_CONFIG_HOME/.config/opensnitch/actions/ allows to overwrite and hence
        personalize the views highlighting colors.
        
     - The columns in the field "cols" start at 0.

     - The order of the customizations are applied from top to bottom, meaning that
     the last "rule" of the "cells" or "rows" arrays will override previous
     rules if there're conflicts. For example:

     [Rules tab]
        Action | Name                | Enabled | ...
         drop  | allow-always-telnet |  False  | ...

