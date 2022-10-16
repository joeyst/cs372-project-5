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

def get_source_and_dest(path):
  text = get_file_lines(path)[0]
  return text.strip().split(" ")

def get_bytes_IP_from_dots_and_numbers(dots_and_numbers):
  numbers = dots_and_numbers.split(".")
  return b''.join([int(num).to_bytes(1, 'big') for num in numbers])

def get_source_and_dest_bytes(path):
  sd = get_source_and_dest(path)
  return [get_bytes_IP_from_dots_and_numbers(path) for path in sd]

print_dict(get_tcp_info('tcp_data_0.dat'))
print(get_source_and_dest('tcp_addrs_0.txt'))
print(get_source_and_dest_bytes('tcp_addrs_0.txt'))