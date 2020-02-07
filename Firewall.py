import pandas as pd
from itertools import product
from collections import defaultdict

#https://stackoverflow.com/questions/22084338/pandas-dataframe-performance
#I was doing research on datastructures to see whether which one would be better for large entries
#I'm not very comfortable with pandas but decided to go with this because of what I read in the stack overflow link.
class Firewall:

    def __init__(self, path):
        #store the csv file into a dataframe and label the columns as such
        self.df = pd.read_csv(path, header=None, names=['direction', 'protocol', 'port', 'ip_address'])

        #calls the private method
        self._parse_rules()

    def _parse_rules(self):
        #initialize a default dict in order to create items easier.
        self.lookup = defaultdict(dict)

        #there are only four combinations for inbound,outound,tcp,udp
        combinations = product(['inbound', 'outbound'], ['tcp', 'udp'])
        for col1, col2 in combinations:
            #create an initial dictionary with port,ip_address dataframes as values
            self.lookup[col1][col2] = self.df[(self.df['direction'] == col1) & (self.df['protocol'] == col2)][
                ['port', 'ip_address']]

            #splits the strings inside of port to turn into a list
            portbounds = self.lookup[col1][col2]['port'].apply(lambda x: x.split('-'))
            corrected_bounds = list()
            #fills a list with an lower and upper bound if applicable, else replace both with the same number
            for boundrange in portbounds:
                if len(boundrange) == 1:
                    corrected_bounds.append([int(boundrange[0])] * 2)
                else:
                    corrected_bounds.append([int(boundrange[0]), int(boundrange[1])])

            #set the current dataframe to a new one with the corrected_bounds
            portrange = pd.DataFrame(corrected_bounds, index=None, columns=['lower_port', 'upper_port'])

            #does the same thing but for ports
            ipbounds = self.lookup[col1][col2]['ip_address'].apply(lambda x: ''.join(x.split('.')).split('-'))
            corrected_bounds = list()
            for boundrange in ipbounds:
                if len(boundrange) == 1:
                    corrected_bounds.append([int(boundrange[0])] * 2)
                else:
                    corrected_bounds.append([int(boundrange[0]), int(boundrange[1])])

            iprange = pd.DataFrame(corrected_bounds, index=None, columns=['lower_ip_address', 'upper_ip_address'])

            #combines two data frames (portrange and iprange) into one data frame
            portrange[iprange.columns] = iprange

            #assign the data frame to the initial dictionary
            self.lookup[col1][col2] = portrange

    def accept_packet(self, direction: str, protocol: str, port: int, ip_address: str):
        #turns the parameter into an int
        ip_address = int(''.join(ip_address.split(".")))
        try:
            #if valid2 then it will continue, else it will fail and return false
            valid_first2 = self.lookup[direction][protocol]

            #returns the dataframe of the valid port numbers with all the ip addresses
            valid_first3 = valid_first2[(valid_first2['lower_port'] <= port) & (port <= valid_first2['upper_port'])][
                ['lower_ip_address', 'upper_ip_address']]

            #iterate through the previous dataframe. "_" is the index which we do not need.
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
