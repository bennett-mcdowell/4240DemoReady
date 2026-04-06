from flask import Flask, render_template, jsonify, request, abort, Response
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect
from wtforms import IntegerField
from wtforms.validators import DataRequired, NumberRange
import logging
import secrets
import ipaddress
from queue import Queue, Empty, Full
from threading import Lock
import json
from datetime import datetime

try:
    from gevent import sleep as _cooperative_sleep
except ImportError:
    from time import sleep as _cooperative_sleep

from .persistence import BlockedIPStore
from .detection import FailedAttempt
from .blocking import BlockingError

logger = logging.getLogger(__name__)

app = Flask(__name__)

app.config['SECRET_KEY'] = secrets.token_hex(16)

csrf = CSRFProtect(app)

blocked_ip_store = BlockedIPStore()
threshold_tracker = None

_daemon = None

_sse_subscribers: list[Queue] = []
_subscribers_lock = Lock()


def set_daemon(daemon):
    global _daemon
    _daemon = daemon


def broadcast_attack_event(failure: FailedAttempt) -> None:
    event_data = {
        'timestamp': failure.timestamp.isoformat(),
        'source_ip': failure.ip,
        'username': failure.username or 'unknown',
        'pattern_type': failure.pattern_type
    }

    message = f"data: {json.dumps(event_data)}\n\n"

    with _subscribers_lock:
        subscriber_count = len(_sse_subscribers)
        logger.debug(f"Broadcasting attack event to {subscriber_count} subscribers: {failure.ip}")

        successful = 0
        for queue in _sse_subscribers:
            try:
                queue.put_nowait(message)
                successful += 1
            except Full:
                logger.warning("Failed to queue message for subscriber (queue full)")

        logger.debug(f"Broadcast complete: {successful}/{subscriber_count} successful")


@app.before_request
def validate_host_header():
    allowed_hosts = ['127.0.0.1', '127.0.0.1:5000', 'localhost', 'localhost:5000']
    host = request.headers.get('Host', '')

    if host not in allowed_hosts:
        logger.warning(f"Rejected request with invalid Host header: {host}")
        abort(403)


@app.route('/')
def dashboard():
    return render_template('dashboard.html')


@app.route('/api/blocked-ips', methods=['GET'])
def blocked_ips_api():
    blocked_ip_store.load()
    blocked_ips = blocked_ip_store.get_all()

    if request.headers.get('HX-Request'):
        if not blocked_ips:
            return '''
            <div class="empty-state">
                <p><strong>No blocked IPs</strong></p>
                <p>No IPs are currently blocked. Blocked IPs will appear here when the daemon detects brute-force attempts.</p>
            </div>
            '''

        from flask_wtf.csrf import generate_csrf
        csrf_token = generate_csrf()

        html = '<table><thead><tr><th>IP Address</th><th>Block Time</th><th>Attempts</th><th>Actions</th></tr></thead><tbody>'
        for blocked in blocked_ips:
            row_id = f"blocked-{blocked.ip.replace('.', '-').replace(':', '-')}"
            html += f'''
            <tr id="{row_id}">
                <td>{blocked.ip}</td>
                <td>{blocked.blocked_at.strftime('%Y-%m-%d %H:%M:%S')}</td>
                <td>{blocked.failure_count}</td>
                <td>
                    <button
                        hx-delete="/api/unblock/{blocked.ip}"
                        hx-headers='{{"X-CSRFToken": "{csrf_token}"}}'
                        hx-target="#{row_id}"
                        hx-swap="outerHTML"
                        hx-confirm="Unblock {blocked.ip}?"
                        class="unblock-btn">
                        Unblock
                    </button>
                </td>
            </tr>
            '''
        html += '</tbody></table>'
        return html
    else:
        return jsonify([b.to_dict() for b in blocked_ips])


@app.route('/api/stats', methods=['GET'])
def stats_api():
    top_offenders = []

    if threshold_tracker is not None:
        failure_counts = {
            ip: len(failures)
            for ip, failures in threshold_tracker._failures.items()
        }

        top_offenders = [
            {"ip": ip, "count": count}
            for ip, count in sorted(
                failure_counts.items(), key=lambda x: x[1], reverse=True
            )[:10]
        ]

    if request.headers.get('HX-Request'):
        if not top_offenders:
            return '''
            <div class="empty-state">
                <p><strong>No attack data</strong></p>
                <p>Top offenders will appear here once attacks are detected.</p>
            </div>
            '''

        html = '<ol>'
        for offender in top_offenders:
            html += f'<li>{offender["ip"]} — {offender["count"]} attempts</li>'
        html += '</ol>'
        return html
    else:
        return jsonify({"top_offenders": top_offenders})


class ConfigForm(FlaskForm):
    threshold = IntegerField('threshold', validators=[
        DataRequired(),
        NumberRange(min=1, max=100, message="Threshold must be between 1 and 100")
    ])
    window_seconds = IntegerField('window_seconds', validators=[
        DataRequired(),
        NumberRange(min=60, max=3600, message="Window must be between 60 and 3600 seconds")
    ])


@app.route('/api/config', methods=['GET'])
def get_config():
    if _daemon is None:
        return jsonify({"error": "Daemon not initialized"}), 500

    return jsonify({
        "threshold": _daemon.config.threshold,
        "window_seconds": _daemon.config.window_seconds
    })


@app.route('/api/config', methods=['POST'])
def update_config():
    form = ConfigForm()

    if not form.validate_on_submit():
        errors = {field: errors[0] for field, errors in form.errors.items()}
        return jsonify({"error": "Validation failed", "details": errors}), 400

    if _daemon is None:
        return jsonify({"error": "Daemon not initialized"}), 500

    try:
        _daemon.config.threshold = form.threshold.data
        _daemon.config.window_seconds = form.window_seconds.data

        from .config import save_config
        save_config(_daemon.config, _daemon.config._config_path)

        reload_success = _daemon.config.reload()
        if not reload_success:
            logger.warning("Config saved but reload failed - daemon may have stale values")

        _daemon.threshold_tracker.threshold = _daemon.config.threshold
        _daemon.threshold_tracker.window_seconds = _daemon.config.window_seconds

        logger.info(f"Config updated via dashboard: threshold={_daemon.config.threshold}, window={_daemon.config.window_seconds}s")

        return jsonify({
            "success": True,
            "message": "Configuration saved. Daemon reloaded settings from file."
        })

    except Exception as e:
        logger.error(f"Failed to save config: {e}")
        return jsonify({"error": "Failed to save configuration"}), 500


@app.route('/api/unblock/<ip>', methods=['DELETE'])
def unblock_ip(ip: str):

    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return jsonify({"error": f"Invalid IP address: {ip}"}), 400

    if _daemon is None:
        return jsonify({"error": "Daemon not initialized"}), 500

    blocked_ips = [b.ip for b in _daemon.blocked_ip_store.get_all()]
    if ip not in blocked_ips:
        return jsonify({"error": f"IP {ip} is not currently blocked"}), 404

    try:
        _daemon.blocking_engine.unblock(ip)
        logger.info(f"Unblocked {ip} via dashboard")

        removed = _daemon.blocked_ip_store.remove(ip)
        if not removed:
            logger.warning(f"IP {ip} removed from iptables but not found in JSON")

        return jsonify({
            "success": True,
            "message": f"IP {ip} unblocked successfully"
        })

    except BlockingError as e:
        logger.error(f"Failed to unblock {ip}: {e}")
        return jsonify({"error": str(e)}), 500
    except Exception as e:
        logger.error(f"Unexpected error unblocking {ip}: {e}")
        return jsonify({"error": "Failed to unblock IP"}), 500


@app.route('/api/stats/graph', methods=['GET'])
def stats_graph():
    if _daemon is None:
        return jsonify({"error": "Daemon not initialized"}), 500

    try:
        stats = _daemon.threshold_tracker.get_attack_stats(hours=24)

        formatted_labels = [
            datetime.fromisoformat(label).strftime('%H:%M')
            for label in stats["labels"]
        ]

        return jsonify({
            "labels": formatted_labels,
            "datasets": [
                {
                    "label": "Attack Attempts",
                    "data": stats["attacks"],
                    "borderColor": "rgb(75, 192, 192)",
                    "tension": 0.1
                }
            ]
        })

    except Exception as e:
        logger.error(f"Failed to get stats: {e}")
        return jsonify({"error": "Failed to load statistics"}), 500


@app.route('/events')
def sse_stream():
    def event_generator():
        queue = Queue(maxsize=50)

        with _subscribers_lock:
            _sse_subscribers.append(queue)
            subscriber_count = len(_sse_subscribers)

        logger.info(f"SSE client connected. Total subscribers: {subscriber_count}")

        try:
            yield "data: {\"type\": \"connected\"}\n\n"

            keepalive_interval_seconds = 30
            seconds_until_keepalive = keepalive_interval_seconds
            while True:
                try:
                    message = queue.get_nowait()
                    logger.debug("Sending SSE message to client")
                    yield message
                    seconds_until_keepalive = keepalive_interval_seconds
                except Empty:
                    if seconds_until_keepalive <= 0:
                        logger.debug("Sending SSE keepalive")
                        yield ": keepalive\n\n"
                        seconds_until_keepalive = keepalive_interval_seconds

                    _cooperative_sleep(1)
                    seconds_until_keepalive -= 1
        finally:
            with _subscribers_lock:
                if queue in _sse_subscribers:
                    _sse_subscribers.remove(queue)
                    subscriber_count = len(_sse_subscribers)

            logger.info(f"SSE client disconnected. Remaining subscribers: {subscriber_count}")

    response = Response(event_generator(), mimetype='text/event-stream')
    response.headers['Cache-Control'] = 'no-cache'
    response.headers['X-Accel-Buffering'] = 'no'
    return response


def run_server(host='127.0.0.1', port=5000, use_gevent=True):
    blocked_ip_store.load()

    if use_gevent:
        from gevent.pywsgi import WSGIServer
        logger.info(f"Starting gevent WSGI server on {host}:{port}")
        server = WSGIServer((host, port), app)
        server.serve_forever()
    else:
        logger.info(f"Starting Flask development server on {host}:{port}")
        app.run(host=host, port=port, debug=False, threaded=True)
