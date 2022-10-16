### getting data from file 
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


### getting file paths 
def get_source_and_dest(path):
  """ gets source and destination path names as strings """
  text = get_file_lines(path)[0]
  return text.strip().split(" ")

def get_bytes_IP_from_dots_and_numbers(dots_and_numbers):
  """ converts given dots and numbers data to bytestring """
  numbers = dots_and_numbers.split(".")
  return b''.join([int(num).to_bytes(1, 'big') for num in numbers])

def get_source_and_dest_bytes(path):
  """ get souce and destination paths as bytestrings """
  sd = get_source_and_dest(path)
  return [get_bytes_IP_from_dots_and_numbers(path) for path in sd]

def get_txt_and_dat_files_from_number(number):
  """ gets file names associated with a certain number """
  txt = "tcp_addrs_{}.txt".format(number)
  addrs = "tcp_data_{}.dat".format(number)
  return txt, addrs


### checksum calculation and verification 
def get_pseudo_header_and_old_checksum(number=0, verbose=False):
  """ 
  gets pseudo header + TCP packet and gets old checksum. 

  The `pseudo_header` variable here is equivalent to the
  `pseudo_header + tcp_data` in the assignment instructions. 
  """
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

  # return the whole packet (pseudo header + TCP data) and the checksum given 
  return pseudo_header, old_checksum 

def calculate_checksum(data):
  """ calculates checksum of packet """
  offset = 0 
  total = 0 
  while offset < len(data): 
    word = int.from_bytes(data[offset:offset+2], 'big') 
    total += word
    total = (total & 0xffff) + (total >> 16)
    offset += 2 
  return (~total) & 0xffff

def is_valid_checksum(number=0, verbose=False):
  """ checks if expected checksum matches actual checksum for a file from given number """
  pseudo_header, expected_checksum = get_pseudo_header_and_old_checksum(number, verbose)
  # pad data if odd length 
  if len(pseudo_header) % 2 == 0:
    pseudo_header += b'\x00'
  actual_checksum = calculate_checksum(pseudo_header)
  return (expected_checksum == actual_checksum)


### checking checksums for all files and getting outputs 
def check_all_checksums(verbose=True):
  """ checks if expected checksum matches actual checksum for each file """
  valids = [is_valid_checksum(number) for number in range(10)]
  expecteds = [True, True, True, True, True, False, False, False, False, False]

  if verbose:
    print("          act. | exp.")
    for (index, valid), expected in zip(enumerate(valids), expecteds):
      print("Index {0: <1} |  {1: <2}  |  {2: <5}".format(index, valid, expected))
  
  all_correct = True
  for valid, expected, in zip(valids, expecteds):
    all_correct &= (valid == expected)
  
  if verbose:
    if all_correct:
      print("All outputs match.")
    else:
      print("An output was wrong.")

  return valids

def print_outputs():
  """ 
  takes outputs from `check_all_checksums` function and prints 
  `PASS` or `FAIL` for each output. 
  """
  valids = check_all_checksums(False)
  for valid in valids:
    if valid == True:
      print("PASS")
    elif valid == False:
      print("FAIL")
    else:
      print("Uhh.")

print_outputs()