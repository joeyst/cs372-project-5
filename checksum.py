def get_file_lines(path):
  """ get UTF-8 string from file path """
  return open(path).readlines()

def get_checksum(data):
  """ get checksum from TCP bytes """
  return int.from_bytes(data[16:18], 'big')

def get_tcp_info(path):
  """ get TCP packet length and checksum from file path """
  data = open(path, "rb").read()
  length = len(data)
  checksum = get_checksum(data)
  return {"length": length, "data": data, "checksum": checksum}

def print_dict(dict):
  for key, value in dict.items():
    try:
      print('{0: <10}| {1: <12}'.format(key, value))
    except:
      print('{0: <10}|'.format(key), value)

print(get_file_lines('tcp_addrs_0.txt'))
tcp_info = get_tcp_info('tcp_data_0.dat')
print_dict(tcp_info)