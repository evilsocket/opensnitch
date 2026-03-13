import sys
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
	# Keep static typing deterministic for linters/IDEs.
	# Runtime still supports both PyQt6/PyQt5 below.
	from PyQt6 import QtCore, QtGui, QtWidgets, uic
	from PyQt6.QtCore import QCoreApplication as QC
	from PyQt6.uic.load_ui import loadUiType as load_ui_type
else:
	if "PyQt6" in sys.modules:
		from PyQt6 import QtCore, QtGui, QtWidgets, uic
		from PyQt6.QtCore import QCoreApplication as QC
		from PyQt6.uic.load_ui import loadUiType as load_ui_type
	elif "PyQt5" in sys.modules:
		from PyQt5 import QtCore, QtGui, QtWidgets, uic
		from PyQt5.QtCore import QCoreApplication as QC

		load_ui_type = uic.loadUiType
	else:
		try:
			from PyQt6 import QtCore, QtGui, QtWidgets, uic
			from PyQt6.QtCore import QCoreApplication as QC
			from PyQt6.uic.load_ui import loadUiType as load_ui_type
		except Exception:
			from PyQt5 import QtCore, QtGui, QtWidgets, uic
			from PyQt5.QtCore import QCoreApplication as QC

			load_ui_type = uic.loadUiType


__all__ = [
	"QtCore",
	"QtGui",
	"QtWidgets",
	"uic",
	"QC",
	"load_ui_type",
	"Any",
	"TYPE_CHECKING",
]

