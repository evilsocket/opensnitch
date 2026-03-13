from opensnitch.plugins.list_subscriptions.ui import QtCore, QC


class UrlTestWorker(QtCore.QThread):
    finished = QtCore.pyqtSignal(bool, str)

    def __init__(self, url: str):
        super().__init__()
        self.url = url

    def run(self):
        import requests

        try:
            response = requests.head(self.url, allow_redirects=True, timeout=5)
            if response.status_code >= 400 and response.status_code not in (403, 405):
                raise requests.HTTPError(f"HTTP {response.status_code}")
            final_url = response.url or self.url
            response.close()
            if response.status_code in (403, 405):
                response = requests.get(
                    self.url, allow_redirects=True, timeout=5, stream=True
                )
                if response.status_code >= 400:
                    raise requests.HTTPError(f"HTTP {response.status_code}")
                final_url = response.url or final_url
                response.close()
            message = QC.translate("stats", "URL reachable.")
            if final_url != self.url:
                message = QC.translate("stats", "URL reachable via redirect.")
                if final_url:
                    message = QC.translate("stats", "URL reachable via redirect.")
                    self.finished.emit(True, f"{message} {final_url}")
                    return
            self.finished.emit(True, message)
        except requests.RequestException as exc:
            self.finished.emit(False, str(exc))