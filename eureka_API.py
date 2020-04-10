# -*- coding: utf-8 -*-

import config
import requests


class API(object):
    config = {
        'network': {
            '_FULL_NODE_PORT': 30013,
            '_NODES_URL': 'http://{}:{}/nodes/',
            '_INBOX_URL': 'http://{}:{}/inbox/',
            '_TRANSACTIONS_URL': 'http://{}:{}/transactions/{}',
            '_TRANSACTIONS_INV_URL': 'http://{}:{}/transactions/block_hash/{}',
            '_BLOCKS_URL': 'http://{}:{}/blocks/{}/{}',
            '_BLOCKS_INV_URL': 'http://{}:{}/blocks/start/{}/end/{}',
            '_HEIGHT_URL': 'http://{}:{}/height',
            '_TRANSACTIONS_HISTORY_URL': 'http://{}:{}/address/{}/transactions',
            '_BALANCE_URL': 'http://{}:{}/address/{}/balance',
            '_DOWNTIME_THRESHOLD': 20,
            '_STATUS_URL': 'http://{}:{}/status/',
            '_CONNECT_URL': 'http://{}:{}/connect/',
            '_MIN_PEERS': 10,
            '_MAX_PEERS': 30
        }
    }
    _FULL_NODE_PORT = 30013
    _NODES_URL = 'http://{}:{}/nodes/'
    _INBOX_URL = 'http://{}:{}/inbox/'
    _TRANSACTIONS_URL = 'http://{}:{}/transactions/{}'
    _TRANSACTIONS_INV_URL = 'http://{}:{}/transactions/block_hash/{}'
    _BLOCKS_URL = 'http://{}:{}/blocks/{}/{}'
    _BLOCKS_INV_URL = 'http://{}:{}/blocks/start/{}/end/{}'
    _HEIGHT_URL = 'http://{}:{}/height'
    _TRANSACTIONS_HISTORY_URL = 'http://{}:{}/address/{}/transactions'
    _BALANCE_URL = 'http://{}:{}/address/{}/balance'
    _DOWNTIME_THRESHOLD = 20
    _STATUS_URL = 'http://{}:{}/status/'
    _CONNECT_URL = 'http://{}:{}/connect/'
    _MIN_PEERS = 10
    _MAX_PEERS = 30

    def __init__(self, peers):
        self.peers = peers

    def request_nodes(self, node, port):
        # get the URL where nodes are to be found
        url = self._NODES_URL.format(node, port)

        try:
            # try asking for nodes
            response = requests.get(url)

            # if we get the nodes, return its json format
            if response.status_code == 200:
                nodes = response.json()
                return nodes

        # but if we don't get anything, try debugging
        except requests.exceptions.RequestException:
            self.peers.record_downtime(node)
            logger.debug('Downtime recorded for host {}'.format(node))

        return None

    def ping_status(self, host):
        url = self._STATUS_URL.format(host, self._FULL_NODE_PORT)

        try:
            response = requests.get(url)
            if response.status_code == 200:
                status_dict = response.json()
                return status_dict ==
