import errno
import os
import time


class FileLock:
    def __init__(self, lock_path: str):
        self.lock_path = lock_path
        self.fd: int | None = None

    def _read_owner_pid(self):
        try:
            with open(self.lock_path, "r", encoding="utf-8") as f:
                raw = f.read().strip()
        except FileNotFoundError:
            return None
        except Exception:
            return -1

        if raw == "":
            return -1
        try:
            return int(raw)
        except Exception:
            return -1

    def _pid_is_alive(self, pid: int):
        if pid <= 0:
            return False
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return False
        except PermissionError:
            return True
        except Exception:
            return True
        return True

    def is_stale(self, max_age: float = 30.0):
        try:
            st = os.stat(self.lock_path)
        except FileNotFoundError:
            return False
        except Exception:
            return False

        pid = self._read_owner_pid()
        if pid is not None and pid > 0 and self._pid_is_alive(pid):
            return False

        age = time.time() - st.st_mtime
        return age > max_age

    def break_stale(self, max_age: float = 30.0):
        if not self.is_stale(max_age=max_age):
            return False
        try:
            os.unlink(self.lock_path)
            return True
        except FileNotFoundError:
            return True
        except Exception:
            return False

    def acquire(self):
        pid = os.getpid()
        flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
        try:
            fd = os.open(self.lock_path, flags, 0o600)
            try:
                os.write(fd, f"{pid}\n".encode("utf-8"))
                os.fsync(fd)
            except Exception:
                try:
                    os.close(fd)
                finally:
                    try:
                        os.unlink(self.lock_path)
                    except Exception:
                        pass
                raise
            self.fd = fd
            return True
        except FileExistsError:
            return False
        except OSError as exc:
            if exc.errno == errno.EEXIST:
                return False
            raise

    def release(self):
        try:
            if self.fd is not None:
                os.close(self.fd)
        finally:
            self.fd = None
            try:
                os.unlink(self.lock_path)
            except FileNotFoundError:
                pass