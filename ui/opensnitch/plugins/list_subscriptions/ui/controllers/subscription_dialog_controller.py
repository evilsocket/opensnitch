from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from opensnitch.plugins.list_subscriptions.ui import QtCore, QtGui, QC
from opensnitch.plugins.list_subscriptions._utils import (
    deslugify_filename,
    derive_filename,
    ensure_filename_type_suffix,
    is_valid_url,
    safe_filename,
)
from opensnitch.plugins.list_subscriptions.ui.workers import UrlTestWorker

if TYPE_CHECKING:
    from opensnitch.plugins.list_subscriptions.ui.views.subscription_dialog import (
        SubscriptionDialog,
    )


class SubscriptionDialogController:
    def __init__(self, *, dialog: "SubscriptionDialog"):
        self._dialog = dialog
        self._refresh_signal: Any = None
        self._url_worker: UrlTestWorker | None = None
        self._url_thread: QtCore.QThread | None = None
        self._url_worker_stopped_callbacks: list[Callable[[], None]] = []
        self._shutting_down = False
        dialog.destroyed.connect(self._on_dialog_destroyed)
        app = QtGui.QGuiApplication.instance()
        if app is not None:
            app.aboutToQuit.connect(self._on_app_about_to_quit)

    def _on_dialog_destroyed(self, *_args):
        self.shutdown_url_worker(wait_ms=3000)

    def _on_app_about_to_quit(self):
        self.shutdown_url_worker(wait_ms=3000)

    def has_active_url_test(self) -> bool:
        thread = self._url_thread
        return bool(thread is not None and thread.isRunning())

    def on_url_test_stopped(self, callback: Callable[[], None]) -> None:
        if not self.has_active_url_test():
            callback()
            return
        self._url_worker_stopped_callbacks.append(callback)

    def cancel_active_url_test(self):
        worker = self._url_worker
        thread = self._url_thread
        if worker is None or thread is None or not thread.isRunning():
            return
        worker.stop()
        thread.quit()

    def wait_for_active_url_test_stop(self, wait_ms: int = 1200) -> bool:
        worker = self._url_worker
        thread = self._url_thread
        if worker is None or thread is None:
            return True
        if not thread.isRunning():
            self._url_worker = None
            self._url_thread = None
            return True

        worker.stop()
        thread.quit()
        if wait_ms <= 0:
            stopped = thread.wait()
        else:
            stopped = thread.wait(wait_ms)
        if stopped:
            self._url_worker = None
            self._url_thread = None
        return bool(stopped)

    def shutdown_url_worker(self, wait_ms: int = 2000) -> bool:
        self._shutting_down = True
        worker = self._url_worker
        thread = self._url_thread
        if worker is None or thread is None:
            self._url_worker = None
            self._url_thread = None
            return True
        try:
            worker.test_result.disconnect(self._dialog._url_test_finished.emit)
        except Exception:
            pass
        if thread.isRunning():
            worker.stop()
            thread.quit()
            if wait_ms <= 0:
                thread.wait()
            else:
                thread.wait(wait_ms)
        if thread.isRunning():
            thread.terminate()
            thread.wait(500)
        if thread.isRunning():
            self._url_worker = worker
            self._url_thread = thread
            return False
        self._url_worker = None
        self._url_thread = None
        return True

    # -- Meta refresh -------------------------------------------------------

    def connect_to_refresh_signal(self, signal: Any) -> None:
        self._refresh_signal = signal
        signal.connect(self.on_state_refreshed)

    def on_state_refreshed(self, url: str, filename: str, meta: dict[str, str]) -> None:
        if url != str(self._dialog._sub.url) or filename != str(self._dialog._sub.filename):
            return
        self.update_meta(meta)

    def update_meta(self, meta: dict[str, str]) -> None:
        self._dialog.meta_file_present.setText(str(meta.get("file_present", "")))
        self._dialog.meta_meta_present.setText(str(meta.get("meta_present", "")))
        self._dialog.meta_state.setText(str(meta.get("state", "")))
        self.apply_meta_state_color(str(meta.get("state", "")))
        self._dialog.meta_last_checked.setText(str(meta.get("last_checked", "")))
        self._dialog.meta_last_updated.setText(str(meta.get("last_updated", "")))
        self._dialog.meta_failures.setText(str(meta.get("failures", "")))
        self._dialog.meta_error.setText(str(meta.get("error", "")))
        self._dialog.meta_list_path.setText(str(meta.get("list_path", "")))
        self._dialog.meta_meta_path.setText(str(meta.get("meta_path", "")))

    def apply_meta_state_color(self, state: str) -> None:
        normalized = (state or "").strip().lower()
        dark_theme = (
            self._dialog.palette()
            .color(QtGui.QPalette.ColorRole.Window)
            .lightness()
            < 128
        )
        if dark_theme:
            healthy_color = "#7CE3A1"
            pending_color = "#F5D76E"
            problematic_color = "#FF8A80"
        else:
            healthy_color = "#0F8A4B"
            pending_color = "#9A6700"
            problematic_color = "#C62828"
        if normalized in ("updated", "not_modified"):
            color = healthy_color
        elif normalized == "pending":
            color = pending_color
        else:
            color = problematic_color
        self._dialog.meta_state.setStyleSheet(f"color: {color};")

    def disconnect_signal(self) -> None:
        self.cancel_active_url_test()
        if self._refresh_signal is not None:
            try:
                self._refresh_signal.disconnect(self.on_state_refreshed)
            except Exception:
                pass
            self._refresh_signal = None

    # -- Field helpers ------------------------------------------------------

    def sync_optional_fields_state(self) -> None:
        self._dialog.interval_units.setEnabled(self._dialog.interval_spin.value() > 0)
        self._dialog.timeout_units.setEnabled(self._dialog.timeout_spin.value() > 0)
        self._dialog.max_size_units.setEnabled(self._dialog.max_size_spin.value() > 0)

    def clear_field_errors(self) -> None:
        self.set_dialog_message("", error=False)
        self._dialog.name_error_label.setText("")
        self._dialog.url_error_label.setText("")
        self._dialog.filename_error_label.setText("")

    def set_dialog_message(self, message: str, error: bool) -> None:
        self._dialog._dialog_message_controller.set_status(message, error=error)
        if (message or "").strip():
            self._dialog.log_message.emit(
                message,
                "ERROR" if error else "INFO",
                str(getattr(self._dialog, "_log_origin", "ui:subscription")),
            )

    # -- URL test -----------------------------------------------------------

    def test_url(self) -> None:
        if self._shutting_down:
            return
        self._dialog.url_error_label.setText("")
        self.set_dialog_message("", error=False)
        url = (self._dialog.url_edit.text() or "").strip()
        if url == "":
            self._dialog.url_error_label.setText(QC.translate("stats", "URL is required."))
            self.set_dialog_message(
                QC.translate("stats", "Fix the highlighted fields."), error=True
            )
            return
        if not is_valid_url(url):
            self._dialog.url_error_label.setText(
                QC.translate("stats", "Enter a valid http:// or https:// URL.")
            )
            self.set_dialog_message(
                QC.translate("stats", "Fix the highlighted fields."), error=True
            )
            return
        self._dialog.test_url_button.setEnabled(False)
        self.set_dialog_message(QC.translate("stats", "Testing URL..."), error=False)
        self.shutdown_url_worker(wait_ms=100)
        self._shutting_down = False
        list_type = (self._dialog.format_combo.currentText() or "hosts").strip().lower()
        thread = QtCore.QThread(self._dialog)
        thread.setObjectName("UrlTestWorkerThread")
        worker = UrlTestWorker(url, list_type)
        worker.setObjectName("UrlTestWorker")
        worker.moveToThread(thread)
        self._url_worker = worker
        self._url_thread = thread
        thread.started.connect(worker.run)
        worker.test_result.connect(self._dialog._url_test_finished.emit)
        worker.finished.connect(thread.quit)
        worker.finished.connect(worker.deleteLater)
        thread.finished.connect(self._on_url_test_worker_stopped)
        thread.finished.connect(thread.deleteLater)
        thread.start()

    def _on_url_test_worker_stopped(self) -> None:
        self._url_worker = None
        self._url_thread = None
        callbacks = self._url_worker_stopped_callbacks[:]
        self._url_worker_stopped_callbacks.clear()
        for callback in callbacks:
            callback()

    def handle_url_test_finished(self, success: bool, message: str) -> None:
        if self._shutting_down:
            return
        self._dialog.test_url_button.setEnabled(True)
        if success:
            self._dialog.url_error_label.setText("")
            self.set_dialog_message(message, error=False)
            return
        self._dialog.url_error_label.setText(QC.translate("stats", "URL check failed."))
        self.set_dialog_message(message, error=True)

    # -- Validation ---------------------------------------------------------

    def validate_then_accept(self) -> None:
        self.clear_field_errors()
        raw_url = (self._dialog.url_edit.text() or "").strip()
        raw_name = (self._dialog.name_edit.text() or "").strip()
        raw_filename = (self._dialog.filename_edit.text() or "").strip()
        list_type = (self._dialog.format_combo.currentText() or "hosts").strip().lower()
        name = raw_name
        filename = safe_filename(raw_filename)
        has_error = False

        if raw_url == "":
            self._dialog.url_error_label.setText(QC.translate("stats", "URL is required."))
            has_error = True
        elif not is_valid_url(raw_url):
            self._dialog.url_error_label.setText(
                QC.translate("stats", "Enter a valid http:// or https:// URL.")
            )
            has_error = True

        if raw_name == "" and raw_filename == "":
            self._dialog.name_error_label.setText(
                QC.translate("stats", "Provide a name or filename.")
            )
            self._dialog.filename_error_label.setText(
                QC.translate("stats", "Provide a filename or name.")
            )
            has_error = True
        elif raw_filename != "" and filename != raw_filename:
            self._dialog.filename_error_label.setText(
                QC.translate("stats", "Filename must not include directory components.")
            )
            has_error = True

        if has_error:
            self.set_dialog_message(
                QC.translate("stats", "Fix the highlighted fields."), error=True
            )
            return

        if filename == "" and name != "":
            filename = safe_filename(derive_filename(name, None, ""))
        filename = ensure_filename_type_suffix(filename, list_type)

        if name == "" and filename != "":
            name = deslugify_filename(filename, list_type)

        self._dialog.name_edit.setText(name)
        self._dialog.filename_edit.setText(filename)
        self._dialog.accept()
