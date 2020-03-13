#!/usr/bin/python

import logging
import logging.handlers
from logging.handlers import RotatingFileHandler

from flask import Flask, Response, jsonify

from ceph_iscsi_config.metrics import GatewayStats

import ceph_iscsi_config.settings as settings
from ceph_iscsi_config.utils import CephiSCSIInval

# Create a flask instance
app = Flask(__name__)


@app.route("/", methods=["GET"])
def prom_root():
    """ handle the '/' endpoint - just redirect point the user at /metrics"""
    return '''<!DOCTYPE html>
    <html>
        <head><title>Ceph/iSCSI Prometheus Exporter</title></head>
        <body>
            <h1>Ceph/iSCSI Prometheus Exporter</h1>
            <p><a href='/metrics'>Metrics</a></p>
        </body>
    </html>'''


@app.route("/metrics", methods=["GET"])
def prom_metrics():
    """ Collect the stats and send back to the caller"""

    stats = GatewayStats()
    try:
        stats.collect()
    except CephiSCSIInval as err:
        return jsonify(message="Could not get metrics: {}".format(err)), 404

    return Response(stats.formatted(),
                    content_type="text/plain")


def main():

    if settings.config.prometheus_exporter:

        logger.info("Integrated Prometheus exporter is enabled")
        # starting a flask instance will occupy the main thread

        # Attach the werkzeug log to the handlers defined in the outer scope
        log = logging.getLogger('werkzeug')
        log.setLevel(logging.DEBUG)
        log.addHandler(file_handler)
        log.addHandler(syslog_handler)

        app.run(host=settings.config.prometheus_host,
                port=settings.config.prometheus_port,
                debug=False,
                threaded=True)

    else:
        logger.info("Integrated Prometheus exporter is disabled")


if __name__ == '__main__':

    settings.init()
    logger_level = logging.getLevelName(settings.config.logger_level)

    # setup syslog handler to help diagnostics
    logger = logging.getLogger('rbd-target-gw')
    logger.setLevel(logging.DEBUG)

    # syslog (systemctl/journalctl messages)
    syslog_handler = logging.handlers.SysLogHandler(address='/dev/log')
    syslog_handler.setLevel(logging.INFO)
    syslog_format = logging.Formatter("%(message)s")
    syslog_handler.setFormatter(syslog_format)

    # file target - more verbose logging for diagnostics
    file_handler = RotatingFileHandler('/var/log/rbd-target-gw/rbd-target-gw.log',
                                       maxBytes=5242880,
                                       backupCount=7)
    file_handler.setLevel(logger_level)
    file_format = logging.Formatter("%(asctime)s [%(levelname)8s] - %(message)s")
    file_handler.setFormatter(file_format)

    logger.addHandler(syslog_handler)
    logger.addHandler(file_handler)

    main()
