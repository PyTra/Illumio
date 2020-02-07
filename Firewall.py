import pandas as pd
from itertools import product
from collections import defaultdict

class Firewall:

    def __init__(self, path):
        self.df = pd.read_csv(path, header=None, names=['direction', 'protocol', 'port', 'ip_address'])
        self._rules = {}
        self.parse_rules()

    def parse_rules(self):
        self.lookup = defaultdict(dict)

        combinations = product(['inbound', 'outbound'], ['tcp', 'udp'])
        for col1, col2 in combinations:
            self.lookup[col1][col2] = self.df[(self.df['direction'] == col1) & (self.df['protocol'] == col2)][
                ['port', 'ip_address']]

            portbounds = self.lookup[col1][col2]['port'].apply(lambda x: x.split('-'))
            corrected_bounds = list()
            for boundrange in portbounds:
                if len(boundrange) == 1:
                    corrected_bounds.append([int(boundrange[0])] * 2)
                else:
                    corrected_bounds.append([int(boundrange[0]), int(boundrange[1])])

            portrange = pd.DataFrame(corrected_bounds, index=None, columns=['lower_port', 'upper_port'])

            ipbounds = self.lookup[col1][col2]['ip_address'].apply(lambda x: ''.join(x.split('.')).split('-'))
            corrected_bounds = list()
            for boundrange in ipbounds:
                if len(boundrange) == 1:
                    corrected_bounds.append([int(boundrange[0])] * 2)
                else:
                    corrected_bounds.append([int(boundrange[0]), int(boundrange[1])])

            iprange = pd.DataFrame(corrected_bounds, index=None, columns=['lower_ip_address', 'upper_ip_address'])
            portrange[iprange.columns] = iprange

            self.lookup[col1][col2] = portrange

    def accept_packet(self, direction: str, protocol: str, port: int, ip_address: str):
        try:
            valid_first2 = self.lookup[direction][protocol]
            valid_first3 = valid_first2[(valid_first2['lower_port'] <= port) & (port <= valid_first2['upper_port'])][
                ['lower_ip_address', 'upper_ip_address']]
            ip_address = int(''.join(ip_address.split(".")))

            for _, (lower, upper) in valid_first3.iterrows():
                if (ip_address <= upper) and (ip_address >= lower):
                    return True
            return False
        except KeyError:
            return False


f = Firewall('rules.csv')
print(f.accept_packet('inbound', 'tcp', 80, '192.168.1.2'))
print(f.accept_packet("inbound", "udp", 53, "192.168.2.1"))
print(f.accept_packet("outbound", "tcp", 10234, "192.168.10.11"))
print(f.accept_packet("inbound", "tcp", 81, "192.168.1.2"))
print(f.accept_packet("inbound", "udp", 24, "52.12.48.92"))
