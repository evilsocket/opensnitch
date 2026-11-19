import os
import json
import threading
from PyQt6 import QtCore, QtWidgets, QtGui
from PyQt6.QtNetwork import QNetworkAccessManager, QNetworkRequest, QNetworkReply

GEOIP_AVAILABLE = False
try:
    import geoip2.database
    GEOIP_AVAILABLE = True
except ImportError:
    pass

WEBENGINE_AVAILABLE = False
try:
    from PyQt6.QtWebEngineWidgets import QWebEngineView
    from PyQt6.QtWebChannel import QWebChannel
    WEBENGINE_AVAILABLE = True
except ImportError:
    pass


class GeoIPLookup:
    """IP geolocation with local DB (preferred) or free HTTP API fallback.

    Priority:
    1. Local GeoLite2-City.mmdb (fastest, offline, needs geoip2 + DB file)
    2. ip-api.com free API (no key, no signup, 45 req/min — cached)
    """
    _instance = None
    GEOIP_DB_PATHS = [
        os.path.expanduser("~/.config/opensnitch/GeoLite2-City.mmdb"),
        "/usr/share/GeoIP/GeoLite2-City.mmdb",
        "/var/lib/GeoIP/GeoLite2-City.mmdb",
        "/usr/local/share/GeoIP/GeoLite2-City.mmdb",
    ]

    @classmethod
    def instance(cls):
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def __init__(self):
        self._reader = None
        self._has_local_db = False
        self._cache = {}
        self._cache_lock = threading.Lock()
        self._load_local_db()

    def _load_local_db(self):
        if not GEOIP_AVAILABLE:
            return

        for path in self.GEOIP_DB_PATHS:
            if os.path.isfile(path):
                try:
                    self._reader = geoip2.database.Reader(path)
                    self._has_local_db = True
                    print("GeoIP database loaded:", path)
                    return
                except Exception as e:
                    print("Error loading GeoIP database:", path, e)

    def is_available(self):
        return True

    def _is_private_ip(self, ip):
        if not ip:
            return True
        parts = ip.split('.')
        if len(parts) != 4:
            return ':' in ip
        try:
            first = int(parts[0])
            second = int(parts[1])
        except ValueError:
            return True
        if first == 10:
            return True
        if first == 172 and 16 <= second <= 31:
            return True
        if first == 192 and second == 168:
            return True
        if first == 127:
            return True
        if first == 0:
            return True
        return False

    def lookup(self, ip):
        if not ip or self._is_private_ip(ip):
            return None

        with self._cache_lock:
            if ip in self._cache:
                return self._cache[ip]

        if self._has_local_db:
            result = self._lookup_local(ip)
            if result:
                with self._cache_lock:
                    self._cache[ip] = result
                return result

        result = self._lookup_api(ip)
        if result:
            with self._cache_lock:
                self._cache[ip] = result
        return result

    def _lookup_local(self, ip):
        try:
            resp = self._reader.city(ip)
            if resp.location.latitude is not None and resp.location.longitude is not None:
                return {
                    'lat': resp.location.latitude,
                    'lon': resp.location.longitude,
                    'city': resp.city.name or "",
                    'country': resp.country.name or "",
                    'country_code': resp.country.iso_code or "",
                }
        except Exception:
            pass
        return None

    def _lookup_api(self, ip):
        """Query ip-api.com — free, no key, 45 req/min."""
        try:
            import urllib.request
            url = f"http://ip-api.com/json/{ip}?fields=status,lat,lon,city,country,countryCode"
            req = urllib.request.Request(url, headers={'User-Agent': 'OpenSnitch/1.0'})
            with urllib.request.urlopen(req, timeout=3) as resp:
                data = json.loads(resp.read().decode())
                if data.get('status') == 'success':
                    return {
                        'lat': data['lat'],
                        'lon': data['lon'],
                        'city': data.get('city', ''),
                        'country': data.get('country', ''),
                        'country_code': data.get('countryCode', ''),
                    }
        except Exception:
            pass
        return None

    def lookup_batch(self, ips):
        """Batch lookup via ip-api.com (up to 100 IPs at once)."""
        uncached = []
        results = {}

        with self._cache_lock:
            for ip in ips:
                if ip in self._cache:
                    results[ip] = self._cache[ip]
                elif not self._is_private_ip(ip):
                    uncached.append(ip)

        if self._has_local_db:
            for ip in uncached:
                r = self._lookup_local(ip)
                if r:
                    results[ip] = r
                    with self._cache_lock:
                        self._cache[ip] = r
            return results

        if not uncached:
            return results

        try:
            import urllib.request
            batch = [{"query": ip, "fields": "status,lat,lon,city,country,countryCode"} for ip in uncached[:100]]
            req = urllib.request.Request(
                "http://ip-api.com/batch",
                data=json.dumps(batch).encode(),
                headers={'Content-Type': 'application/json', 'User-Agent': 'OpenSnitch/1.0'},
                method='POST'
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read().decode())
                for i, item in enumerate(data):
                    if item.get('status') == 'success':
                        ip = uncached[i]
                        r = {
                            'lat': item['lat'],
                            'lon': item['lon'],
                            'city': item.get('city', ''),
                            'country': item.get('country', ''),
                            'country_code': item.get('countryCode', ''),
                        }
                        results[ip] = r
                        with self._cache_lock:
                            self._cache[ip] = r
        except Exception:
            pass

        return results


class _MapCanvas(QtWidgets.QWidget):
    """Pure QPainter world map with zoom/pan, cached base layer, country labels."""

    BG = QtGui.QColor("#181825")
    OCEAN = QtGui.QColor("#1a1a2e")
    LAND = QtGui.QColor("#2a2a3c")
    LAND_BORDER = QtGui.QColor("#45475a")
    GRID = QtGui.QColor(69, 71, 90, 30)
    LABEL_COLOR = QtGui.QColor(166, 173, 200, 100)
    LABEL_COLOR_BRIGHT = QtGui.QColor(166, 173, 200, 160)
    HOME_COLOR = QtGui.QColor("#89b4fa")
    ALLOWED_COLOR = QtGui.QColor("#a6e3a1")
    BLOCKED_COLOR = QtGui.QColor("#f38ba8")
    TEXT_COLOR = QtGui.QColor("#cdd6f4")
    TEXT_DIM = QtGui.QColor("#a6adc8")
    TEXT_MUTED = QtGui.QColor("#585b70")

    MIN_ZOOM = 1.0
    MAX_ZOOM = 20.0

    _COUNTRIES = None

    @classmethod
    def _load_data(cls):
        if cls._COUNTRIES is not None:
            return
        data_path = os.path.join(os.path.dirname(__file__), "world_map.json")
        if os.path.exists(data_path):
            with open(data_path) as f:
                raw = json.load(f)
            for c in raw:
                total_pts = sum(len(poly) for poly in c.get('p', []))
                c['_size'] = total_pts
            cls._COUNTRIES = raw
        else:
            cls._COUNTRIES = []

    _BTN_SIZE = 32
    _BTN_MARGIN = 12
    _BTN_GAP = 4

    def __init__(self, parent=None):
        super().__init__(parent)
        self._load_data()
        self.setMinimumSize(400, 250)
        self._home = None
        self._markers = {}
        self._allowed = 0
        self._blocked = 0
        self._tooltip_key = None
        self._tooltip_pos = None

        self._zoom = 1.0
        self._center_lon = 0.0
        self._center_lat = 20.0
        self._dragging = False
        self._drag_start = None
        self._drag_center = None
        self._hover_btn = None

        self._base_cache = None
        self._base_cache_key = None
        self.setMouseTracking(True)
        self.setFocusPolicy(QtCore.Qt.FocusPolicy.WheelFocus)

    def _viewport(self):
        """Return (lon_min, lon_max, lat_min, lat_max) of visible area."""
        w, h = self.width(), self.height()
        lon_span = 360.0 / self._zoom
        lat_span = 180.0 / self._zoom
        aspect = w / max(h, 1) * (180.0 / 360.0)
        if aspect > 1:
            lat_span = lon_span / aspect * (180.0 / 360.0)
        else:
            lon_span = lat_span * aspect * (360.0 / 180.0)
        return (
            self._center_lon - lon_span / 2,
            self._center_lon + lon_span / 2,
            self._center_lat - lat_span / 2,
            self._center_lat + lat_span / 2,
        )

    def _lonlat_to_xy(self, lon, lat):
        w, h = self.width(), self.height()
        vp = self._viewport()
        lon_span = vp[1] - vp[0]
        lat_span = vp[3] - vp[2]
        x = (lon - vp[0]) / lon_span * w
        y = (vp[3] - lat) / lat_span * h
        return x, y

    def _xy_to_lonlat(self, x, y):
        w, h = self.width(), self.height()
        vp = self._viewport()
        lon_span = vp[1] - vp[0]
        lat_span = vp[3] - vp[2]
        lon = vp[0] + x / w * lon_span
        lat = vp[3] - y / h * lat_span
        return lon, lat

    def _clamp_center(self):
        self._center_lon = max(-180, min(180, self._center_lon))
        self._center_lat = max(-85, min(85, self._center_lat))

    def _btn_rects(self):
        w, h = self.width(), self.height()
        s = self._BTN_SIZE
        m = self._BTN_MARGIN
        g = self._BTN_GAP
        x = w - m - s
        by = h - m - s * 3 - g * 2
        return {
            'in': QtCore.QRectF(x, by, s, s),
            'out': QtCore.QRectF(x, by + s + g, s, s),
            'reset': QtCore.QRectF(x, by + (s + g) * 2, s, s),
        }

    def _zoom_in(self):
        self._zoom = min(self.MAX_ZOOM, self._zoom * 1.5)
        self._clamp_center()
        self._invalidate_cache()
        self.update()

    def _zoom_out(self):
        self._zoom = max(self.MIN_ZOOM, self._zoom / 1.5)
        self._clamp_center()
        self._invalidate_cache()
        self.update()

    def _zoom_reset(self):
        self._zoom = 1.0
        self._center_lon = 0.0
        self._center_lat = 20.0
        self._invalidate_cache()
        self.update()

    def _invalidate_cache(self):
        self._base_cache = None

    def set_home(self, lat, lon):
        self._home = (lat, lon)
        self.update()

    def add_marker(self, key, lat, lon, color, info):
        if key not in self._markers:
            self._markers[key] = {'lat': lat, 'lon': lon, 'color': color, 'conns': []}
        self._markers[key]['conns'].append(info)
        self._markers[key]['color'] = color

    def set_counts(self, allowed, blocked):
        self._allowed = allowed
        self._blocked = blocked

    def _country_visible(self, country, vp):
        """Quick check if any polygon point is in the viewport."""
        for poly in country.get('p', []):
            for lon, lat in poly:
                if vp[0] <= lon <= vp[1] and vp[2] <= lat <= vp[3]:
                    return True
        return False

    def _label_min_size(self):
        """Min polygon point count to show label at current zoom."""
        if self._zoom >= 8:
            return 3
        elif self._zoom >= 4:
            return 5
        elif self._zoom >= 2:
            return 10
        else:
            return 30

    def _render_base(self):
        w, h = self.width(), self.height()
        vp = self._viewport()
        pixmap = QtGui.QPixmap(w, h)
        p = QtGui.QPainter(pixmap)
        p.setRenderHint(QtGui.QPainter.RenderHint.Antialiasing)

        p.fillRect(0, 0, w, h, self.OCEAN)

        # grid — adapt spacing to zoom
        base_step = 30
        if self._zoom >= 6:
            base_step = 5
        elif self._zoom >= 3:
            base_step = 10

        pen = QtGui.QPen(self.GRID, 0.5)
        p.setPen(pen)
        lat_start = int(vp[2] / base_step) * base_step
        for lat in range(lat_start, int(vp[3]) + base_step, base_step):
            _, y = self._lonlat_to_xy(0, lat)
            if 0 <= y <= h:
                p.drawLine(QtCore.QPointF(0, y), QtCore.QPointF(w, y))
        lon_start = int(vp[0] / base_step) * base_step
        for lon in range(lon_start, int(vp[1]) + base_step, base_step):
            x, _ = self._lonlat_to_xy(lon, 0)
            if 0 <= x <= w:
                p.drawLine(QtCore.QPointF(x, 0), QtCore.QPointF(x, h))

        # countries
        border_width = 0.6 if self._zoom < 4 else 1.0
        p.setPen(QtGui.QPen(self.LAND_BORDER, border_width))
        p.setBrush(QtGui.QBrush(self.LAND))
        for country in self._COUNTRIES:
            for poly in country.get('p', []):
                path = QtGui.QPainterPath()
                for i, (lon, lat) in enumerate(poly):
                    x, y = self._lonlat_to_xy(lon, lat)
                    if i == 0:
                        path.moveTo(x, y)
                    else:
                        path.lineTo(x, y)
                path.closeSubpath()
                p.drawPath(path)

        # country labels — zoom-dependent, collision-aware
        min_size = self._label_min_size()
        label_size = max(7, min(11, int(6 + self._zoom * 0.8)))
        label_font = QtGui.QFont()
        label_font.setPointSize(label_size)
        label_font.setWeight(QtGui.QFont.Weight.Normal if self._zoom < 3 else QtGui.QFont.Weight.Medium)
        p.setFont(label_font)
        p.setPen(self.LABEL_COLOR if self._zoom < 3 else self.LABEL_COLOR_BRIGHT)
        fm = QtGui.QFontMetrics(label_font)
        fh = fm.height()
        pad = 4

        candidates = []
        for country in self._COUNTRIES:
            name = country.get('n', '')
            centroid = country.get('c', [])
            if not name or not centroid:
                continue
            if country['_size'] < min_size:
                continue
            cx, cy = self._lonlat_to_xy(centroid[0], centroid[1])
            if cx < -50 or cx > w + 50 or cy < -20 or cy > h + 20:
                continue
            candidates.append((country['_size'], name, cx, cy))
        candidates.sort(key=lambda x: -x[0])

        placed = []
        for _, name, cx, cy in candidates:
            tw = fm.horizontalAdvance(name)
            lx = cx - tw / 2
            ly = cy - fh / 2
            rect = (lx - pad, ly - pad, tw + pad * 2, fh + pad * 2)
            overlap = False
            for pr in placed:
                if not (rect[0] > pr[0] + pr[2] or rect[0] + rect[2] < pr[0] or
                        rect[1] > pr[1] + pr[3] or rect[1] + rect[3] < pr[1]):
                    overlap = True
                    break
            if overlap:
                continue
            placed.append(rect)
            p.drawText(QtCore.QPointF(lx, cy + fm.ascent() / 2), name)

        p.end()
        return pixmap

    def resizeEvent(self, event):
        self._invalidate_cache()
        super().resizeEvent(event)

    def wheelEvent(self, event):
        delta = event.angleDelta().y()
        pos = event.position() if hasattr(event, 'position') else event.pos()
        lon_before, lat_before = self._xy_to_lonlat(pos.x(), pos.y())

        if delta > 0:
            self._zoom = min(self.MAX_ZOOM, self._zoom * 1.25)
        else:
            self._zoom = max(self.MIN_ZOOM, self._zoom / 1.25)

        lon_after, lat_after = self._xy_to_lonlat(pos.x(), pos.y())
        self._center_lon -= (lon_after - lon_before)
        self._center_lat -= (lat_after - lat_before)
        self._clamp_center()
        self._invalidate_cache()
        self.update()

    def _hit_button(self, pos):
        for name, rect in self._btn_rects().items():
            if rect.contains(pos):
                return name
        return None

    def mousePressEvent(self, event):
        if event.button() == QtCore.Qt.MouseButton.LeftButton:
            pos = event.position() if hasattr(event, 'position') else event.pos()
            btn = self._hit_button(pos)
            if btn == 'in':
                self._zoom_in()
                return
            elif btn == 'out':
                self._zoom_out()
                return
            elif btn == 'reset':
                self._zoom_reset()
                return
            self._dragging = True
            self._drag_start = (pos.x(), pos.y())
            self._drag_center = (self._center_lon, self._center_lat)
            self.setCursor(QtCore.Qt.CursorShape.ClosedHandCursor)
        elif event.button() == QtCore.Qt.MouseButton.MiddleButton:
            self._zoom_reset()

    def mouseReleaseEvent(self, event):
        if event.button() == QtCore.Qt.MouseButton.LeftButton:
            self._dragging = False
            self.setCursor(QtCore.Qt.CursorShape.ArrowCursor)

    def mouseMoveEvent(self, event):
        pos = event.position() if hasattr(event, 'position') else event.pos()

        if self._dragging and self._drag_start:
            dx = pos.x() - self._drag_start[0]
            dy = pos.y() - self._drag_start[1]
            vp = self._viewport()
            lon_per_px = (vp[1] - vp[0]) / self.width()
            lat_per_px = (vp[3] - vp[2]) / self.height()
            self._center_lon = self._drag_center[0] - dx * lon_per_px
            self._center_lat = self._drag_center[1] + dy * lat_per_px
            self._clamp_center()
            self._invalidate_cache()
            self.update()
            return

        # button hover
        btn = self._hit_button(pos)
        if btn != self._hover_btn:
            self._hover_btn = btn
            self.setCursor(QtCore.Qt.CursorShape.PointingHandCursor if btn else QtCore.Qt.CursorShape.ArrowCursor)
            self.update()

        # tooltip hit test
        if not btn:
            hit = None
            for key, m in self._markers.items():
                mx, my = self._lonlat_to_xy(m['lon'], m['lat'])
                hit_radius = max(8, 12 / max(self._zoom * 0.3, 1))
                if abs(pos.x() - mx) < hit_radius and abs(pos.y() - my) < hit_radius:
                    hit = key
                    break
            if hit != self._tooltip_key:
                self._tooltip_key = hit
                self._tooltip_pos = (pos.x(), pos.y()) if hit else None
                self.update()

    def mouseDoubleClickEvent(self, event):
        if event.button() == QtCore.Qt.MouseButton.LeftButton:
            pos = event.position() if hasattr(event, 'position') else event.pos()
            lon, lat = self._xy_to_lonlat(pos.x(), pos.y())
            self._center_lon = lon
            self._center_lat = lat
            self._zoom = min(self.MAX_ZOOM, self._zoom * 2)
            self._clamp_center()
            self._invalidate_cache()
            self.update()

    def paintEvent(self, event):
        w, h = self.width(), self.height()
        if w < 2 or h < 2:
            return

        cache_key = (w, h, self._zoom, round(self._center_lon, 4), round(self._center_lat, 4))
        if self._base_cache is None or self._base_cache_key != cache_key:
            self._base_cache = self._render_base()
            self._base_cache_key = cache_key

        p = QtGui.QPainter(self)
        p.setRenderHint(QtGui.QPainter.RenderHint.Antialiasing)

        # cached base
        p.drawPixmap(0, 0, self._base_cache)

        # arcs from home
        if self._home:
            hx, hy = self._lonlat_to_xy(self._home[1], self._home[0])
            for m in self._markers.values():
                color = QtGui.QColor(m['color'])
                color.setAlpha(60)
                pen = QtGui.QPen(color, 1.0)
                pen.setDashPattern([4, 6])
                p.setPen(pen)
                mx, my = self._lonlat_to_xy(m['lon'], m['lat'])
                path = QtGui.QPainterPath()
                path.moveTo(hx, hy)
                cx = (hx + mx) / 2
                cy = min(hy, my) - abs(mx - hx) * 0.1
                path.quadTo(cx, cy, mx, my)
                p.drawPath(path)

        # destination markers
        p.setPen(QtCore.Qt.PenStyle.NoPen)
        for m in self._markers.values():
            x, y = self._lonlat_to_xy(m['lon'], m['lat'])
            if x < -20 or x > w + 20 or y < -20 or y > h + 20:
                continue
            color = QtGui.QColor(m['color'])
            n = min(len(m['conns']), 10)
            radius = (3 + n * 0.4) * min(self._zoom * 0.5, 2)

            glow = QtGui.QColor(color)
            glow.setAlpha(40)
            p.setBrush(glow)
            p.drawEllipse(QtCore.QPointF(x, y), radius + 4, radius + 4)
            p.setBrush(color)
            p.drawEllipse(QtCore.QPointF(x, y), radius, radius)

        # home marker
        if self._home:
            hx, hy = self._lonlat_to_xy(self._home[1], self._home[0])
            r = 7 * min(self._zoom * 0.4, 1.5)
            p.setBrush(QtGui.QBrush(self.HOME_COLOR))
            p.setPen(QtGui.QPen(QtGui.QColor("#181825"), 2))
            p.drawEllipse(QtCore.QPointF(hx, hy), r, r)

        # stats panel
        font = p.font()
        font.setPointSize(9)
        font.setWeight(QtGui.QFont.Weight.Medium)
        p.setFont(font)
        panel_y = h - 65
        panel_bg = QtGui.QColor(24, 24, 37, 220)
        panel_rect = QtCore.QRectF(12, panel_y, 190, 55)
        p.setPen(QtCore.Qt.PenStyle.NoPen)
        p.setBrush(panel_bg)
        p.drawRoundedRect(panel_rect, 6, 6)

        p.setPen(self.TEXT_COLOR)
        p.drawText(QtCore.QPointF(20, panel_y + 17),
                   f"Destinations: {len(self._markers)}")
        p.setPen(self.ALLOWED_COLOR)
        p.drawText(QtCore.QPointF(20, panel_y + 33),
                   f"Allowed: {self._allowed}")
        p.setPen(self.BLOCKED_COLOR)
        p.drawText(QtCore.QPointF(20, panel_y + 49),
                   f"Blocked: {self._blocked}")

        # zoom controls
        btns = self._btn_rects()
        btn_bg = QtGui.QColor(30, 30, 46, 220)
        btn_hover_bg = QtGui.QColor(49, 50, 68, 240)
        btn_border = QtGui.QColor(69, 71, 90, 120)
        btn_font = QtGui.QFont()
        btn_font.setPointSize(14)
        btn_font.setWeight(QtGui.QFont.Weight.Bold)

        for name, rect in btns.items():
            is_hover = (self._hover_btn == name)
            p.setPen(QtGui.QPen(btn_border, 0.5))
            p.setBrush(btn_hover_bg if is_hover else btn_bg)
            p.drawRoundedRect(rect, 6, 6)
            p.setFont(btn_font)
            p.setPen(self.TEXT_COLOR if is_hover else self.TEXT_DIM)
            if name == 'in':
                label = "+"
            elif name == 'out':
                label = "−"
            else:
                btn_font_sm = QtGui.QFont()
                btn_font_sm.setPointSize(9)
                btn_font_sm.setWeight(QtGui.QFont.Weight.Medium)
                p.setFont(btn_font_sm)
                label = "↺"
            p.drawText(rect, QtCore.Qt.AlignmentFlag.AlignCenter, label)

        if self._zoom > 1.05:
            zoom_font = QtGui.QFont()
            zoom_font.setPointSize(7)
            p.setFont(zoom_font)
            p.setPen(self.TEXT_MUTED)
            zt = f"{self._zoom:.1f}x"
            zr = btns['reset']
            p.drawText(QtCore.QPointF(zr.x() + (zr.width() - QtGui.QFontMetrics(zoom_font).horizontalAdvance(zt)) / 2, zr.y() + zr.height() + 12), zt)

        # tooltip
        if self._tooltip_key and self._tooltip_key in self._markers:
            self._draw_tooltip(p)

        p.end()

    def _draw_tooltip(self, p):
        m = self._markers[self._tooltip_key]
        x, y = self._tooltip_pos or self._lonlat_to_xy(m['lon'], m['lat'])

        conns = m['conns']
        city = conns[0].get('city', '') if conns else ''
        country = conns[0].get('country', '') if conns else ''
        location = f"{city}, {country}" if city else country
        header = location or f"{m['lat']:.1f}, {m['lon']:.1f}"
        lat_dir = 'N' if m['lat'] >= 0 else 'S'
        lon_dir = 'E' if m['lon'] >= 0 else 'W'
        coord_line = f"{abs(m['lat']):.2f}°{lat_dir}  {abs(m['lon']):.2f}°{lon_dir}"
        ip_line = conns[0].get('ip', '') if conns else ''

        # aggregate duplicate connections
        from collections import Counter
        conn_counts = Counter()
        conn_action = {}
        for c in conns:
            proc = os.path.basename(c['process']) if '/' in c['process'] else c['process']
            key = (proc, c['dst'], c['action'])
            conn_counts[key] += 1
            conn_action[key] = c['action']

        sorted_conns = conn_counts.most_common(6)
        lines = []
        for (proc, dst, action), count in sorted_conns:
            is_allow = 'allow' in action.lower()
            prefix = "✓" if is_allow else "✗"
            suffix = f" ({count})" if count > 1 else ""
            lines.append((prefix, f" {proc} → {dst}{suffix}", action))
        remaining = len(conn_counts) - 6
        if remaining > 0:
            lines.append(("", f"  +{remaining} more unique connections", ""))

        font_header = QtGui.QFont()
        font_header.setPointSize(10)
        font_header.setWeight(QtGui.QFont.Weight.Bold)
        font_body = QtGui.QFont()
        font_body.setPointSize(8)
        font_coord = QtGui.QFont()
        font_coord.setPointSize(7)

        fm_h = QtGui.QFontMetrics(font_header)
        fm_b = QtGui.QFontMetrics(font_body)
        fm_c = QtGui.QFontMetrics(font_coord)

        body_widths = [fm_b.horizontalAdvance(l[0] + l[1]) for l in lines] if lines else [0]
        tw = max(fm_h.horizontalAdvance(header),
                 fm_c.horizontalAdvance(coord_line + "  " + ip_line),
                 max(body_widths)) + 28
        tw = max(tw, 220)
        header_h = 46
        th = header_h + len(lines) * 17 + 10

        tx = x + 14
        ty = y - th - 8
        if tx + tw > self.width():
            tx = x - tw - 14
        if ty < 0:
            ty = y + 14

        # background
        p.setPen(QtCore.Qt.PenStyle.NoPen)
        p.setBrush(QtGui.QColor(30, 30, 46, 245))
        p.drawRoundedRect(QtCore.QRectF(tx, ty, tw, th), 8, 8)
        p.setPen(QtGui.QPen(QtGui.QColor("#45475a"), 0.5))
        p.drawRoundedRect(QtCore.QRectF(tx, ty, tw, th), 8, 8)

        # header
        p.setFont(font_header)
        p.setPen(self.TEXT_COLOR)
        p.drawText(QtCore.QPointF(tx + 10, ty + 18), header)

        # coordinates + IP
        p.setFont(font_coord)
        p.setPen(self.TEXT_MUTED)
        info = coord_line
        if ip_line:
            info += f"   {ip_line}"
        p.drawText(QtCore.QPointF(tx + 10, ty + 32), info)

        # separator
        p.setPen(QtGui.QPen(QtGui.QColor("#45475a"), 0.5))
        p.drawLine(QtCore.QPointF(tx + 8, ty + header_h - 4),
                   QtCore.QPointF(tx + tw - 8, ty + header_h - 4))

        # connections
        p.setFont(font_body)
        for i, (prefix, text, action) in enumerate(lines):
            row_y = ty + header_h + 10 + i * 17
            is_allowed = 'allow' in action.lower() if action else True
            p.setPen(self.ALLOWED_COLOR if is_allowed else self.BLOCKED_COLOR)
            p.drawText(QtCore.QPointF(tx + 10, row_y), prefix)
            p.setPen(self.TEXT_DIM)
            p.drawText(QtCore.QPointF(tx + 10 + fm_b.horizontalAdvance(prefix), row_y), text)


class _GeoWorker(QtCore.QObject):
    """Runs GeoIP lookups off the main thread."""
    finished = QtCore.pyqtSignal(list)  # list of (conn_id, dst_ip, action, process, dst_host, geo_dict_or_None)
    home_resolved = QtCore.pyqtSignal(float, float)

    def __init__(self, geoip):
        super().__init__()
        self._geoip = geoip

    @QtCore.pyqtSlot(list)
    def resolve_batch(self, items):
        unique_ips = list({item[1] for item in items if item[1]})
        geo_map = {}
        for i in range(0, len(unique_ips), 100):
            chunk = unique_ips[i:i+100]
            geo_map.update(self._geoip.lookup_batch(chunk))
        results = []
        for item in items:
            results.append((*item, geo_map.get(item[1])))
        self.finished.emit(results)

    @QtCore.pyqtSlot()
    def resolve_home(self):
        geo = self._geoip._lookup_api("")
        if geo is None:
            geo = self._geoip.lookup("8.8.8.8")
        if geo:
            self.home_resolved.emit(geo['lat'], geo['lon'])
        else:
            self.home_resolved.emit(51.5, -0.1)


class WorldMapWidget(QtWidgets.QWidget):
    _resolve_batch_signal = QtCore.pyqtSignal(list)
    _resolve_home_signal = QtCore.pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("mapTab")
        layout = QtWidgets.QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        self._geoip = GeoIPLookup.instance()
        self._canvas = _MapCanvas()
        self._home_set = False
        self._allowed_count = 0
        self._blocked_count = 0
        layout.addWidget(self._canvas)

        self._pending_queue = []
        self._flush_timer = QtCore.QTimer(self)
        self._flush_timer.setSingleShot(True)
        self._flush_timer.setInterval(100)
        self._flush_timer.timeout.connect(self._flush_pending)

        self._worker_thread = QtCore.QThread(self)
        self._worker = _GeoWorker(self._geoip)
        self._worker.moveToThread(self._worker_thread)
        self._resolve_batch_signal.connect(self._worker.resolve_batch)
        self._resolve_home_signal.connect(self._worker.resolve_home)
        self._worker.finished.connect(self._on_batch_resolved)
        self._worker.home_resolved.connect(self._on_home_resolved)
        self._worker_thread.start()

    def set_home(self, lat, lon):
        self._home_set = True
        self._canvas.set_home(lat, lon)

    def add_connection(self, conn_id, dst_ip, action, process, dst_host=""):
        self._pending_queue.append((conn_id, dst_ip, action, process, dst_host))
        if not self._flush_timer.isActive():
            self._flush_timer.start()

    def _flush_pending(self):
        if not self._pending_queue:
            return
        batch = self._pending_queue[:]
        self._pending_queue.clear()
        self._resolve_batch_signal.emit(batch)

    @QtCore.pyqtSlot(list)
    def _on_batch_resolved(self, results):
        if not self._home_set:
            self._try_set_home()

        for conn_id, dst_ip, action, process, dst_host, geo in results:
            if geo is None:
                continue

            is_blocked = action.lower() in ('deny', 'drop', 'reject')
            if is_blocked:
                self._blocked_count += 1
                color = "#f38ba8"
            else:
                self._allowed_count += 1
                color = "#a6e3a1"

            key = f"{geo['lat']:.2f},{geo['lon']:.2f}"
            self._canvas.add_marker(key, geo['lat'], geo['lon'], color, {
                'process': process or "",
                'dst': dst_host or dst_ip,
                'action': action,
                'ip': dst_ip,
                'city': geo.get('city', ''),
                'country': geo.get('country', ''),
            })

        self._canvas.set_counts(self._allowed_count, self._blocked_count)
        self._canvas.update()

    def _try_set_home(self):
        self._home_set = True
        self._canvas.set_home(51.5, -0.1)
        self._resolve_home_signal.emit()

    @QtCore.pyqtSlot(float, float)
    def _on_home_resolved(self, lat, lon):
        self.set_home(lat, lon)
        self._canvas.update()

    def clear_connections(self):
        self._canvas._markers.clear()
        self._canvas._home = None
        self._home_set = False
        self._allowed_count = 0
        self._blocked_count = 0
        self._canvas.set_counts(0, 0)
        self._canvas.update()

    def is_available(self):
        return True

    def cleanup(self):
        self._worker_thread.quit()
        self._worker_thread.wait(2000)
