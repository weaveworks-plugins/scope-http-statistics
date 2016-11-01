#!/usr/bin/env python
import bcc

import time
import collections
import datetime
import os
import signal
import errno
import json
try:
    from urllib.parse import urlparse
except ImportError:
    from urlparse import urlparse
import threading
import socket
import BaseHTTPServer
import SocketServer
import string
import shutil

EBPF_PROGRAM = "ebpf-http-statistics.c"
EBPF_REQUEST_RATE_TABLE_NAME = "received_http_requests"
EBPF_RESPONSE_CODE_TABLE_NAME = "sent_http_responses"
PLUGIN_ID="http-statistics"
PLUGIN_UNIX_SOCK = "/var/run/scope/plugins/" + PLUGIN_ID + "/" + PLUGIN_ID + ".sock"

# Keep in sync with ebpf-http-statistics.c enum http_codes
idx_to_http_code = {
    "0":    "100",

    "1":    "200",
    "2":    "201",
    "3":    "102",
    "4":    "204",

    "5":    "308",

    "6":    "400",
    "7":    "401",
    "8":    "403",
    "9":    "404",
    "10":   "408",
    "11":   "451",

    "12":   "500",
    "13":   "501",
    "14":   "502",
    "15":   "501",

    "16":   "OTHERS",
}

class KernelInspector(threading.Thread):
    def __init__(self):
        super(KernelInspector, self).__init__()
        self.bpf = bcc.BPF(EBPF_PROGRAM)
        self.http_request_rate_per_pid = dict()
        self.http_resp_code_rate_per_pid = dict()
        self.lock = threading.Lock()

    def update_http_request_rate_per_pid(self, last_req_count_snapshot):
        # Aggregate the kernel's per-task http request counts into userland's
        # per-process counts
        req_count_table = self.bpf.get_table(EBPF_REQUEST_RATE_TABLE_NAME)
        new_req_count_snapshot = collections.defaultdict(int)
        for pid_tgid, req_count in req_count_table.iteritems():
            # Note that the kernel's tgid maps into userland's pid
            # (not to be confused by the kernel's pid, which is
            # the unique identifier of a kernel task)
            pid = pid_tgid.value >> 32
            new_req_count_snapshot[pid] += req_count.value

        # Compute request rate
        new_http_request_rate_per_pid = dict()
        for pid, req_count in new_req_count_snapshot.iteritems():
            request_delta = req_count
            if pid in last_req_count_snapshot:
                 request_delta -= last_req_count_snapshot[pid]
            new_http_request_rate_per_pid[pid] = request_delta

        self.lock.acquire()
        self.http_request_rate_per_pid = new_http_request_rate_per_pid
        self.lock.release()

        return new_req_count_snapshot

    def update_http_resp_per_pid(self, last_resp_count_snapshot):
        # Aggregate the kernel's per-task http response code counts into userland's
        # per-process counts
        resp_count_table = self.bpf.get_table(EBPF_RESPONSE_CODE_TABLE_NAME)
        new_resp_count_snapshot = collections.defaultdict(dict)

        for pid_tgid, codes_counts in resp_count_table.iteritems():
            # Note that the kernel's tgid maps into userland's pid
            # (not to be confused by the kernel's pid, which is
            # the unique identifier of a kernel task)
            pid = pid_tgid.value >> 32
            new_resp_count_snapshot[pid] = collections.defaultdict(int)

            for code in range(len(codes_counts.codes)):
                code_count = codes_counts.codes[code]
                if code not in new_resp_count_snapshot[pid]:
                    new_resp_count_snapshot[pid][code] = 0
                new_resp_count_snapshot[pid][code] += code_count

        # Compute response codes rate
        new_http_resp_code_rate_per_pid = dict()
        for pid, resp_codes in new_resp_count_snapshot.iteritems():
            if pid not in new_http_resp_code_rate_per_pid:
                new_http_resp_code_rate_per_pid[pid] = collections.defaultdict(dict)
            for code in resp_codes:
                resp_code_delta = resp_codes[code]
                if pid in last_resp_count_snapshot:
                    resp_code_delta -= last_resp_count_snapshot[pid][code]
                new_http_resp_code_rate_per_pid[pid][code] = resp_code_delta

        self.lock.acquire()
        self.http_resp_code_rate_per_pid = new_http_resp_code_rate_per_pid
        self.lock.release()

        return new_resp_count_snapshot

    def on_http_request_rate_per_pid(self, f):
        self.lock.acquire()
        r = f(self.http_request_rate_per_pid)
        self.lock.acquire()
        return r

    def on_http_resp_per_pid(self, f):
        self.lock.acquire()
        r = f(self.http_resp_code_rate_per_pid)
        self.lock.release()
        return r

    def on_http_stats(self, f):
        self.lock.acquire()
        r = f(self.http_request_rate_per_pid, self.http_resp_code_rate_per_pid)
        self.lock.release()
        return r

    def run(self):
        # Compute request rates based on the requests counts from the last
        # second. It would be simpler to clear the table, wait one second but
        # clear() is expensive (each entry is individually cleared with a system
        # call) and less robust (it contends with the increments done by the
        # kernel probe).
        req_count_snapshot = collections.defaultdict(int)
        resp_count_snapshot = collections.defaultdict(dict)
        while True:
            time.sleep(1)
            req_count_snapshot = self.update_http_request_rate_per_pid(req_count_snapshot)
            resp_count_snapshot = self.update_http_resp_per_pid(resp_count_snapshot)


class PluginRequestHandler(BaseHTTPServer.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def __init__(self, *args, **kwargs):
        self.request_log = ''
        BaseHTTPServer.BaseHTTPRequestHandler.__init__(self, *args, **kwargs)

    def do_GET(self):
        self.log_extra = ''
        path = urlparse(self.path)[2].lower()
        if path == '/report':
            self.do_report()
        else:
            self.send_response(404)
            self.send_header('Content-length', 0)
            self.end_headers()

    def get_process_nodes(self, http_request_rate_per_pid, http_resp_code_rate_per_pid):
        # Get current timestamp in RFC3339
        date = datetime.datetime.utcnow()
        date = date.isoformat('T') + 'Z'
        process_nodes = collections.defaultdict(dict)
        for pid, http_request_rate in http_request_rate_per_pid.iteritems():
            node_key = "%s;%d" % (self.server.hostname, pid)
            if node_key not in process_nodes:
                process_nodes[node_key] = collections.defaultdict(dict)
                process_nodes[node_key]['metrics'] = collections.defaultdict(dict)

            process_nodes[node_key]['metrics']['http_requests_per_second'] = {
                'samples': [{
                    'date': date,
                    'value': float(http_request_rate),
                }]
            }
        response_code_key_list = list()
        for pid, http_responses_code_rate in http_resp_code_rate_per_pid.iteritems():
            node_key = "%s;%d" % (self.server.hostname, pid)
            for code, rate in http_responses_code_rate.iteritems():
                if rate == 0:
                    continue
                if node_key not in process_nodes:
                    process_nodes[node_key] = collections.defaultdict(dict)
                    process_nodes[node_key]['metrics'] = collections.defaultdict(dict)

                response_code_key = 'http_' + idx_to_http_code[str(code)] + '_responses_per_second'
                response_code_key_list.append(response_code_key)
                process_nodes[node_key]['metrics'][response_code_key] = {
                    'samples': [{
                        'date': date,
                        'value': float(rate),
                    }]
                }

        return process_nodes, response_code_key_list

    def do_report(self):
        kernel_inspector = self.server.kernel_inspector
        process_nodes, response_code_key_list = kernel_inspector.on_http_stats(self.get_process_nodes)
        metric_templates = collections.defaultdict(dict)
        priority = 0.1
        metric_templates['http_requests_per_second'] = {
                        'id':       'http_requests_per_second',
                        'label':    'HTTP Req/Second',
                        'priority': priority,
        }
        for response_code_key in response_code_key_list:
            http_code = string.split(response_code_key, '_')[1]
            http_code_priority = http_code
            if http_code == "OTHERS":
                http_code_priority = "1000"
            metric_templates[response_code_key] = {
                'id': response_code_key,
                'label': 'HTTP Resp ' + http_code + '/Second',
                'priority': (float(http_code_priority) / 1000),
            }
        report = {
            'Process': {
                'nodes': process_nodes,
                'metric_templates': metric_templates,
            },
            'Plugins': [
              {
                'id': PLUGIN_ID,
                'label': 'HTTP Statistics',
                'description': 'Adds http request metrics to processes',
                'interfaces': ['reporter'],
                'api_version': '1',
              }
            ]
        }
        body = json.dumps(report)
        self.request_log = "resp_size=%d, resp_entry_count=%d" % (len(body), len(process_nodes))
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.send_header('Content-length', len(body))
        self.end_headers()
        self.wfile.write(body)

    def log_request(self, code='-', size='-'):
        request_log = ''
        if self.request_log:
            request_log = ' (%s)' % self.request_log
        self.log_message('"%s" %s %s%s',
                         self.requestline, str(code), str(size), request_log)


class PluginServer(SocketServer.ThreadingUnixStreamServer):
    daemon_threads = True

    def __init__(self, socket_file, kernel_inspector):
        self.socket_file = socket_file
        self.delete_plugin_directory()
        mkdir_p(os.path.dirname(socket_file))
        self.kernel_inspector = kernel_inspector
        self.hostname = socket.gethostname()
        SocketServer.UnixStreamServer.__init__(self, socket_file, PluginRequestHandler)

    def finish_request(self, request, _):
        # Make the logger happy by providing a phony client_address
        self.RequestHandlerClass(request, '-', self)

    def delete_plugin_directory(self):
        if os.path.exists(os.path.dirname(self.socket_file)):
            shutil.rmtree(os.path.dirname(self.socket_file), ignore_errors=True)


def mkdir_p(path):
    try:
        # we set the permissions to 0700, because only owner and root should be able to access to the plugin directory
        os.makedirs(path, mode=0o700)
    except OSError as exc:
        if exc.errno == errno.EEXIST and os.path.isdir(path):
            pass
        else:
            raise


if __name__ == '__main__':
    kernel_inspector = KernelInspector()
    kernel_inspector.setDaemon(True)
    kernel_inspector.start()
    plugin_server = PluginServer(PLUGIN_UNIX_SOCK, kernel_inspector)

    def sig_handler(b, a):
        plugin_server.delete_plugin_directory()
        exit(0)
    signal.signal(signal.SIGTERM, sig_handler)
    signal.signal(signal.SIGINT, sig_handler)
    try:
        plugin_server.serve_forever()
    except:
        plugin_server.delete_plugin_directory()
        raise
