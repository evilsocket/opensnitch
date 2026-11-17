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


LEAFLET_HTML = """<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/leaflet.min.css" />
<script src="https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/leaflet.min.js"></script>
<style>
  * { margin: 0; padding: 0; }
  body { background: #181825; overflow: hidden; }
  #map {
    width: 100vw;
    height: 100vh;
    background: #181825;
  }
  .leaflet-container { background: #181825; }
  .leaflet-tile-pane {
    filter: invert(1) hue-rotate(180deg) brightness(0.7) contrast(1.3);
  }
  .connection-popup {
    font-family: 'Segoe UI', 'Noto Sans', sans-serif;
    font-size: 12px;
    line-height: 1.4;
  }
  .connection-popup .allowed { color: #a6e3a1; }
  .connection-popup .blocked { color: #f38ba8; }
  .connection-popup b { color: #cdd6f4; }
  .leaflet-popup-content-wrapper {
    background: #313244 !important;
    color: #cdd6f4 !important;
    border-radius: 8px !important;
    border: 1px solid #45475a;
  }
  .leaflet-popup-tip { background: #313244 !important; }
  .stats-panel {
    position: absolute;
    bottom: 20px;
    left: 20px;
    background: rgba(30, 30, 46, 0.9);
    border: 1px solid #313244;
    border-radius: 8px;
    padding: 10px 14px;
    color: #cdd6f4;
    font-family: 'Segoe UI', sans-serif;
    font-size: 12px;
    z-index: 1000;
    pointer-events: none;
  }
  .stats-panel .count { font-weight: 700; font-size: 14px; }
  .stats-panel .allowed { color: #a6e3a1; }
  .stats-panel .blocked { color: #f38ba8; }
</style>
</head>
<body>
<div id="map"></div>
<div class="stats-panel" id="statsPanel">
  <div>Destinations: <span class="count" id="destCount">0</span></div>
  <div>Allowed: <span class="count allowed" id="allowedCount">0</span></div>
  <div>Blocked: <span class="count blocked" id="blockedCount">0</span></div>
</div>
<script>
var map = L.map('map', {
  center: [30, 0],
  zoom: 2,
  minZoom: 2,
  maxZoom: 10,
  zoomControl: true,
  attributionControl: false
});

L.tileLayer('https://tile.openstreetmap.org/{z}/{x}/{y}.png', {
  maxZoom: 19
}).addTo(map);

var markers = {};
var arcs = {};
var homeLat = null;
var homeLon = null;
var homeMarker = null;
var allowedCount = 0;
var blockedCount = 0;

function setHome(lat, lon) {
  homeLat = lat;
  homeLon = lon;
  if (homeMarker) map.removeLayer(homeMarker);
  homeMarker = L.circleMarker([lat, lon], {
    radius: 8,
    fillColor: '#89b4fa',
    color: '#89b4fa',
    weight: 2,
    opacity: 1,
    fillOpacity: 0.8
  }).addTo(map).bindPopup('<div class="connection-popup"><b>Your Location</b></div>');
}

function addConnection(id, lat, lon, city, country, action, process, dst_host) {
  var isAllowed = action.toLowerCase() !== 'deny' && action.toLowerCase() !== 'drop' && action.toLowerCase() !== 'reject';
  var color = isAllowed ? '#a6e3a1' : '#f38ba8';

  if (isAllowed) allowedCount++; else blockedCount++;

  var key = lat.toFixed(2) + ',' + lon.toFixed(2);

  if (!markers[key]) {
    markers[key] = {
      marker: L.circleMarker([lat, lon], {
        radius: 5,
        fillColor: color,
        color: color,
        weight: 1,
        opacity: 0.9,
        fillOpacity: 0.7
      }).addTo(map),
      connections: []
    };
  }

  var info = {process: process, dst: dst_host || (city + ', ' + country), action: action};
  markers[key].connections.push(info);

  var popupHtml = '<div class="connection-popup">';
  popupHtml += '<b>' + (city ? city + ', ' : '') + country + '</b><br>';
  var last5 = markers[key].connections.slice(-5);
  for (var i = 0; i < last5.length; i++) {
    var c = last5[i];
    var cls = (c.action.toLowerCase() === 'deny' || c.action.toLowerCase() === 'drop') ? 'blocked' : 'allowed';
    popupHtml += '<span class="' + cls + '">' + c.action + '</span> ' + c.process + ' → ' + c.dst + '<br>';
  }
  if (markers[key].connections.length > 5) {
    popupHtml += '... and ' + (markers[key].connections.length - 5) + ' more';
  }
  popupHtml += '</div>';
  markers[key].marker.bindPopup(popupHtml);

  // draw arc from home
  if (homeLat !== null) {
    if (arcs[key]) map.removeLayer(arcs[key]);
    arcs[key] = L.polyline(
      arcPoints([homeLat, homeLon], [lat, lon]),
      {color: color, weight: 1.5, opacity: 0.4, dashArray: '4 6'}
    ).addTo(map);
  }

  document.getElementById('destCount').textContent = Object.keys(markers).length;
  document.getElementById('allowedCount').textContent = allowedCount;
  document.getElementById('blockedCount').textContent = blockedCount;
}

function arcPoints(from, to, numPoints) {
  numPoints = numPoints || 20;
  var points = [];
  for (var i = 0; i <= numPoints; i++) {
    var t = i / numPoints;
    var lat = from[0] + t * (to[0] - from[0]);
    var lon = from[1] + t * (to[1] - from[1]);
    // arc curvature
    var d = Math.sqrt(Math.pow(to[0]-from[0],2) + Math.pow(to[1]-from[1],2));
    var arc = Math.sin(Math.PI * t) * d * 0.15;
    lat += arc;
    points.push([lat, lon]);
  }
  return points;
}

function clearConnections() {
  for (var k in markers) {
    map.removeLayer(markers[k].marker);
  }
  for (var k in arcs) {
    map.removeLayer(arcs[k]);
  }
  markers = {};
  arcs = {};
  allowedCount = 0;
  blockedCount = 0;
  document.getElementById('destCount').textContent = '0';
  document.getElementById('allowedCount').textContent = '0';
  document.getElementById('blockedCount').textContent = '0';
}
</script>
</body>
</html>"""


class WorldMapFallback(QtWidgets.QWidget):
    """Fallback widget when QWebEngineView is not available."""
    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QtWidgets.QVBoxLayout(self)
        layout.setAlignment(QtCore.Qt.AlignmentFlag.AlignCenter)

        icon_label = QtWidgets.QLabel()
        icon_label.setAlignment(QtCore.Qt.AlignmentFlag.AlignCenter)
        icon_label.setStyleSheet("font-size: 48px; color: #585b70;")
        icon_label.setText("\U0001F30D")
        layout.addWidget(icon_label)

        msg = QtWidgets.QLabel("World Map requires PyQt6-WebEngine")
        msg.setAlignment(QtCore.Qt.AlignmentFlag.AlignCenter)
        msg.setStyleSheet("font-size: 14px; color: #a6adc8; font-weight: 600;")
        layout.addWidget(msg)

        hint = QtWidgets.QLabel("Install with: pip3 install PyQt6-WebEngine")
        hint.setAlignment(QtCore.Qt.AlignmentFlag.AlignCenter)
        hint.setStyleSheet("font-size: 12px; color: #585b70;")
        layout.addWidget(hint)


class WorldMapWidget(QtWidgets.QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("mapTab")
        layout = QtWidgets.QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        self._geoip = GeoIPLookup.instance()
        self._web_view = None
        self._page_loaded = False
        self._pending_commands = []
        self._home_set = False

        if WEBENGINE_AVAILABLE:
            self._web_view = QWebEngineView()
            self._web_view.setHtml(LEAFLET_HTML)
            self._web_view.loadFinished.connect(self._on_load_finished)
            layout.addWidget(self._web_view)
        else:
            layout.addWidget(WorldMapFallback())

    def _on_load_finished(self, ok):
        if ok:
            self._page_loaded = True
            for cmd in self._pending_commands:
                self._run_js(cmd)
            self._pending_commands.clear()

    def _run_js(self, js):
        if self._web_view is None:
            return
        if not self._page_loaded:
            self._pending_commands.append(js)
            return
        self._web_view.page().runJavaScript(js)

    def set_home(self, lat, lon):
        self._home_set = True
        self._run_js(f"setHome({lat}, {lon});")

    def add_connection(self, conn_id, dst_ip, action, process, dst_host=""):
        geo = self._geoip.lookup(dst_ip)
        if geo is None:
            return

        if not self._home_set:
            self._try_set_home()

        city = geo['city'].replace("'", "\\'")
        country = geo['country'].replace("'", "\\'")
        process_safe = process.replace("'", "\\'") if process else ""
        dst_host_safe = dst_host.replace("'", "\\'") if dst_host else ""

        self._run_js(
            f"addConnection('{conn_id}', {geo['lat']}, {geo['lon']}, "
            f"'{city}', '{country}', '{action}', '{process_safe}', '{dst_host_safe}');"
        )

    def _try_set_home(self):
        geo = self._geoip._lookup_api("")
        if geo is None:
            geo = self._geoip.lookup("8.8.8.8")
        if geo:
            self.set_home(geo['lat'], geo['lon'])
            return
        self.set_home(51.5, -0.1)

    def clear_connections(self):
        self._run_js("clearConnections();")

    def is_available(self):
        return WEBENGINE_AVAILABLE
