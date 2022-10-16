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

def get_txt_and_dat_files_from_number(number):
  txt = "tcp_addrs_{}.txt".format(number)
  addrs = "tcp_data_{}.dat".format(number)
  return txt, addrs

def get_pseudo_header_and_old_checksum(number=0, verbose=False):
  txt, dat = get_txt_and_dat_files_from_number(number)

  # get info from text file 
  source, dest = get_source_and_dest_bytes(txt)
  if verbose:
    print("Source:", source, "\nDest  :", dest)
    print("Dest #:", dest[n])
  zero = b'\x00'
  ptcl = b'\x06'

  # get info from data file
  tcp_info = get_tcp_info(dat)
  tcp_length = tcp_info['length']
  old_checksum = tcp_info['checksum']
  tcp_data = tcp_info['data']
  # reset `tcp_data` to have `0` as checksum value
  tcp_data = tcp_data[:16] + b'\x00\x00' + tcp_data[18:]

  # creating the pseudo header
  ip_header = source + dest + zero + ptcl + int.to_bytes(tcp_length, 2, 'big')
  pseudo_header = ip_header + tcp_data
  return pseudo_header, old_checksum 

print_dict(get_tcp_info('tcp_data_0.dat'))
print(get_source_and_dest('tcp_addrs_0.txt'))
print(get_source_and_dest_bytes('tcp_addrs_0.txt'))
print(get_txt_and_dat_files_from_number(0))
print(get_pseudo_header_and_old_checksum())