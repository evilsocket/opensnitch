from typing import Any

from opensnitch.plugins.list_subscriptions.ui import QtCore, QC
from opensnitch.plugins.list_subscriptions._utils import is_hosts_file_like


class UrlTestWorker(QtCore.QObject):
    test_result = QtCore.pyqtSignal(bool, str)
    finished = QtCore.pyqtSignal()

    def __init__(self, url: str, list_type: str = "hosts"):
        super().__init__()
        self.url = url
        self.list_type = (list_type or "hosts").strip().lower()
        self._stop_requested = False
        self._active_response: Any = None

    def stop(self) -> None:
        self._stop_requested = True
        resp = self._active_response
        if resp is not None:
            try:
                resp.close()
            except Exception:
                pass

    def _should_stop(self) -> bool:
        return self._stop_requested

    @QtCore.pyqtSlot()
    def run(self):
        import requests

        try:
            if self._should_stop():
                return
            # HEAD has no interruptible response object; keep timeout short.
            response = requests.head(self.url, allow_redirects=True, timeout=3)
            if response.status_code >= 400 and response.status_code not in (403, 405):
                raise requests.HTTPError(f"HTTP {response.status_code}")
            final_url = response.url or self.url
            response.close()
            if self._should_stop():
                return
            if response.status_code in (403, 405):
                response = requests.get(
                    self.url, allow_redirects=True, timeout=3, stream=True
                )
                self._active_response = response
                if response.status_code >= 400:
                    raise requests.HTTPError(f"HTTP {response.status_code}")
                final_url = response.url or final_url
                response.close()
                self._active_response = None
                if self._should_stop():
                    return
            message = QC.translate("stats", "URL reachable.")
            if self.list_type == "hosts":
                sample_lines: list[str] = []
                response = requests.get(
                    self.url,
                    allow_redirects=True,
                    timeout=5,
                    stream=True,
                )
                self._active_response = response
                if response.status_code >= 400:
                    raise requests.HTTPError(f"HTTP {response.status_code}")

                for chunk in response.iter_content(chunk_size=32 * 1024):
                    if self._should_stop():
                        return
                    if not chunk:
                        continue
                    txt = chunk.decode("utf-8", errors="ignore")
                    for line in txt.splitlines():
                        if len(sample_lines) < 200:
                            sample_lines.append(line)
                        else:
                            break
                    if len(sample_lines) >= 200:
                        break
                response.close()
                self._active_response = None

                if not is_hosts_file_like(sample_lines):
                    self.test_result.emit(
                        False,
                        QC.translate(
                            "stats",
                            "URL is reachable but content is not valid hosts format.",
                        ),
                    )
                    return

            if final_url != self.url:
                message = QC.translate("stats", "URL reachable via redirect.")
                if final_url:
                    message = QC.translate("stats", "URL reachable via redirect.")
                    self.test_result.emit(True, f"{message} {final_url}")
                    return
            self.test_result.emit(True, message)
        except requests.RequestException as exc:
            if not self._should_stop():
                self.test_result.emit(False, str(exc))
        finally:
            self._active_response = None
            self.finished.emit()