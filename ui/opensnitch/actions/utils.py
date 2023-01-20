from PyQt5.QtGui import QColor

def getColorNames():
    """Return the built-in color names that can be used to choose new colors:
        https://doc.qt.io/qtforpython-5/PySide2/QtGui/QColor.html#predefined-colors
        https://www.w3.org/TR/SVG11/types.html#ColorKeywords
    """
    return QColor.colorNames()
