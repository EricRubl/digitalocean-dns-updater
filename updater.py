import datetime
import json
import logging
import sys
import syslog
import time
import urllib.error
import urllib.request
from functools import wraps

import yaml

from job import Job

APIURL = "https://api.digitalocean.com/v2"
LOGGER = logging.getLogger('dns_updater')


class ConfigException(Exception):
    pass


class SyncError(Exception):
    pass


class Config:
    def __init__(self):
        try:
            with open('/etc/digitalocean-dns-updater/config.yml', 'r') as f:
                self.config = yaml.load(f, Loader=yaml.FullLoader)
        except IOError:
            raise ConfigException('Error opening config file')

        self.logfile = self.config.get('logfile')
        self.domain = self.config.get('domain')
        self.token = self.config.get('token')
        self.interval = self.config.get('interval')
        self.records = self.config.get('records')
        self.update_main_record = self.config.get('update_main_record')

        if not self.logfile:
            raise ConfigException('No logfile provided')
        if type(self.logfile) is not str:
            raise ConfigException('logfile format is not correct')
        if not self.domain:
            raise ConfigException('No domain provided')
        if type(self.domain) is not str:
            raise ConfigException('domain format is not correct')
        if not self.interval:
            raise ConfigException('No interval provided')
        if type(self.interval) is not int:
            raise ConfigException('interval format is not correct')
        if not self.token:
            raise ConfigException('No token provided')
        if type(self.token) is not str:
            raise ConfigException('token format is not correct')


def retry(times=5, delay=1.0, exceptions=(Exception, urllib.error.HTTPError)):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            count = 0
            while True:
                try:
                    count = count + 1
                    return f(*args, **kwargs)
                except exceptions as e:
                    if count == times:
                        raise e
                    time.sleep(delay)
        return wrapper
    return decorator


def generate_request_headers(token, extra_headers=None):
    rv = {'Authorization': "Bearer {}".format(token)}
    if extra_headers:
        rv.update(extra_headers)
    return rv


@retry()
def http_get(url, headers=None):
    if headers:
        req = urllib.request.Request(url, headers=headers)
    else:
        req = urllib.request.Request(url)
    with urllib.request.urlopen(req) as file:
        data = file.read()
        return data.decode('utf8')


@retry()
def http_put(url, data, headers):
    req = urllib.request.Request(url, data=data, headers=headers)
    req.get_method = lambda: 'PUT'
    with urllib.request.urlopen(req) as file:
        data = file.read()
        return data.decode('utf8')


def get_external_ip():
    try:
        external_ip = http_get('http://ipinfo.io/ip')
    except (Exception, urllib.error.HTTPError):
        raise SyncError('Error getting external IP')
    return external_ip.rstrip()


def get_record(domain, name, rtype, token):
    url = "{}/domains/{}/records".format(APIURL, domain)

    while True:
        try:
            result = json.loads(http_get(url, headers=generate_request_headers(token)))
        except (Exception, urllib.error.HTTPError):
            raise SyncError('Error getting DNS record')

        for record in result['domain_records']:
            if record['type'] == rtype and record['name'] == name:
                return record

        if 'pages' in result['links'] and 'next' in result['links']['pages']:
            url = result['links']['pages']['next']
            # Replace http to https.
            # DigitalOcean forces https request, but links are returned as http
            url = url.replace("http://", "https://")
        else:
            break

    raise SyncError("Could not find DNS record {}".format(name + ' ' + rtype))


def set_record_ip(domain, record, ip, token):
    url = "{}/domains/{}/records/{}".format(APIURL, domain, record['id'])
    data = json.dumps({'data': ip}).encode('utf-8')
    headers = generate_request_headers(token, {'Content-Type': 'application/json'})

    try:
        result = json.loads(http_put(url, data, headers))
    except (Exception, urllib.error.HTTPError):
        raise SyncError('Error setting DNS record')

    if result['domain_record']['data'] != ip:
        LOGGER.warning('DNS record did not update accordingly')


def get_dns_ip(config):
    if config.update_main_record:
        record_name = '@'
        record_type = 'A'
    else:
        # Use the first record
        record_name = config.records[0].get('name')
        record_type = config.records[0].get('type')

    record = get_record(config.domain, record_name, record_type, config.token)
    dns_ip = record.get('data')

    if dns_ip is not None:
        return dns_ip
    else:
        raise SyncError('No IP returned from DNS')


def sync(config):
    try:
        dns_ip = get_dns_ip(config)
        actual_ip = get_external_ip()

        if dns_ip != actual_ip:
            LOGGER.info('External IP changed from {} to {}'.format(dns_ip, actual_ip))

            if config.update_main_record:
                # update root A record
                root_a_record = get_record(config.domain, '@', 'A', config.token)
                set_record_ip(config.domain, root_a_record, actual_ip, config.token)
                LOGGER.info('Updated {} A record with IP {}'.format(config.domain, actual_ip))

            # update other records according to config file
            for record in config.records:
                if record.get('type') == 'A':
                    a_record = get_record(config.domain, record.get('name'), 'A', config.token)
                    set_record_ip(config.domain, a_record, actual_ip, config.token)
                    LOGGER.info('Updated {} A record with IP {}'.format(record.get('name') + '.' + config.domain,
                                                                        actual_ip))
        else:
            syslog.syslog(syslog.LOG_INFO, 'External IP {} did not change'.format(actual_ip))
    except SyncError as ex:
        LOGGER.error(str(ex))


def run():
    try:
        config = Config()
    except ConfigException as ex:
        print(ex)
        sys.exit(1)

    LOGGER.setLevel(logging.DEBUG)
    file_handler = logging.FileHandler(config.logfile)
    file_handler.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(asctime)s | %(levelname)s | %(message)s')
    file_handler.setFormatter(formatter)
    LOGGER.addHandler(file_handler)

    job = Job(logger=LOGGER, interval=datetime.timedelta(seconds=config.interval), execute=sync, config=config)

    LOGGER.info('Starting daemon')

    job.start()


if __name__ == '__main__':
    run()
