import argparse
import socket
import struct
import time

# зациукливание на разных машинах,

class Cache:
    def __init__(self):
        self.cache = {}

    def add(self, rdata, a_type, a_class, a_ttl, domain):
        key = (domain, a_class, a_type)
        self.cache[key] = {'data': rdata, 'ttl': a_ttl, 'timestamp': time.time()}

    def get(self, domain, a_class, a_type):
        key = (domain, a_class, a_type)
        if key not in self.cache:
            #print("данный ключ не найден в кэше")
            return None, None

        target_info = self.cache[key]
        current_time = time.time()
        age = current_time - target_info['timestamp']

        if age >= target_info['ttl']:
            #print("запись устарела")
            del self.cache[key]
            return None, None

        remaining_ttl = int(target_info['ttl'] - age)
        #print(f"Кэш хит, оставшееся время: {remaining_ttl}")
        return remaining_ttl, target_info['data']



def socket_listener(input_port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    if input_port:
        sock.bind(('0.0.0.0', input_port))
    elif not input_port:
        sock.bind(('0.0.0.0', 53))

    print('Listening on port {}'.format(input_port))

    data, addr = sock.recvfrom(1024)
    sock.close()
    return data, addr

def read_name(data, offset):
    parts = []
    start_offset = offset
    jumped = False
    while True:
        if data[offset] == 0:
            offset += 1
            break

        if data[offset] >= 0xC0:
            if not jumped:
                start_offset = offset + 2
            jumped = True

            pointer_offset = ((data[offset] & 0x3F) << 8) | data[offset + 1]
            offset = pointer_offset
        else:
            length = data[offset]
            offset += 1
            parts.append(data[offset: offset + length].decode('utf-8'))
            offset += length

    if not jumped:
        start_offset = offset

    return '.'.join(parts), start_offset

def encode_name(domain):
    if not domain:
        return b'\x00'
    encoded = b''
    for part in domain.split('.'):
        encoded += bytes([len(part)]) + part.encode('utf-8')
    encoded += b'\x00'
    return encoded

def forwarder(data_bytes, forwarder_ip, forwarder_port=53):
    forwarder_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    forwarder_socket.settimeout(3)
    try:
        forwarder_socket.sendto(data_bytes, (forwarder_ip, forwarder_port))
        response = forwarder_socket.recv(4096)
        return response

    except socket.timeout:
        print('forward socket timed out')
        return None

    finally:
        forwarder_socket.close()

def forward_parser(data_bytes, cache):
    response = struct.unpack('>HHHHHH', data_bytes[:12])
    qd = response[2]
    an = response[3]

    if an == 0:
        return

    offset = 12
    domain = ""

    for i in range(qd):
        parsed_domain, offset = read_name(data_bytes, offset)
        if i == 0:
            domain = parsed_domain
        offset += 4

    # Создаем словари для сортировки ответов по их типам
    grouped_rdata = {}
    ttl_info = {}
    class_info = {}

    for _ in range(an):
        _, offset = read_name(data_bytes, offset)
        resource_record = struct.unpack('>HHIH', data_bytes[offset: offset + 10])
        offset += 10

        a_type = resource_record[0]
        a_class = resource_record[1]
        a_ttl = resource_record[2]
        a_rdata_length = resource_record[3]

        if a_type in [2, 5, 12]: # ns cname ptr
            target_domain, _ = read_name(data_bytes, offset)
            rdata = target_domain
        elif a_type == 15:
            pref = struct.unpack('>H', data_bytes[offset:offset + 2])[0]
            target_domain, _ = read_name(data_bytes, offset + 2)
            rdata = {'pref': pref, 'domain': target_domain}
        else:
            rdata = data_bytes[offset: offset + a_rdata_length]

        offset += a_rdata_length

        # Раскладываем ответы по правильным "коробкам" (по их a_type)
        if a_type not in grouped_rdata:
            grouped_rdata[a_type] = []
            ttl_info[a_type] = a_ttl
            class_info[a_type] = a_class

        grouped_rdata[a_type].append(rdata)

    # Сохраняем каждую независимую группу в кэш отдельно
    for t, data_list in grouped_rdata.items():
        cache.add(data_list, t, class_info[t], ttl_info[t], domain)


def response_packet(original_request, question_length, a_type, a_class, remaining_ttl, rdata_list):
    unpacked_header = struct.unpack('>HHHHHH', original_request[:12])
    tid = unpacked_header[0]
    flags = unpacked_header[1]
    qd = unpacked_header[2]
    ns = unpacked_header[4]
    ar = unpacked_header[5]
    new_flags = flags | 0b1000000000000000

    new_an = len(rdata_list)

    new_answer_header = struct.pack('>HHHHHH', tid, new_flags, qd, new_an, ns, ar)
    question_section = original_request[12: 12 + question_length]
    name_pointer = b'\xc0\x0c'  # указатель на 12 байт

    answer_section = b''

    # Теперь мы пакуем каждый ответ из списка в цикле
    for item in rdata_list:
        if a_type in [2, 5, 12]:  # NS CNAME PTR
            encoded_rdata = encode_name(item)
        elif a_type == 15:  # MX
            encoded_domain = encode_name(item['domain'])
            encoded_rdata = struct.pack('>H', item['pref']) + encoded_domain
        else:  # в остальных доменных имен нету
            encoded_rdata = item

        answer_param = struct.pack('>HHIH', a_type, a_class, remaining_ttl, len(encoded_rdata))
        answer_section += name_pointer + answer_param + encoded_rdata

    final_packet = new_answer_header + question_section + answer_section
    return final_packet


def client_request(raw_bytes):

    offset = 12
    domain_parts = []
    while raw_bytes[offset] != 0:
        part_length = raw_bytes[offset]
        offset += 1
        part = raw_bytes[offset: offset + part_length].decode('utf-8')
        domain_parts.append(part)
        offset += part_length

    domain = '.'.join(domain_parts)
    offset += 1

    q_info = struct.unpack('>HH', raw_bytes[offset: offset + 4])
    q_type = q_info[0]
    q_class = q_info[1]
    offset = offset + 4
    question_length = offset - 12
    return domain, q_type, q_class, question_length

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='кеширующий DNS сервер')

    parser.add_argument('-p', '--port', type = int, default = 53,
                        help = "Порт на котором будет работать сервер")

    parser.add_argument('-f', '--forwarder', type = str, required = True,
                        help = "IP старшего ДНС сервера")

    args = parser.parse_args()

    my_cache = Cache()

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    server_socket.bind(('0.0.0.0', args.port))

    print(f"DNS сервер запущен на порту: {args.port}")
    print(f"Старший сервер: {args.forwarder}")
    print("Ожидание трафика...")

    QTYPES = {1: 'A', 2: 'NS', 5: 'CNAME', 12: 'PTR', 15: 'MX', 16: 'TXT', 28: 'AAAA', 6: 'SOA'}

    active_requests = {}
    LOOP_TIMEOUT = 5

    while True:
        try:
            client_data, client_address = server_socket.recvfrom(1024)
            client_ip = client_address[0]

            tid = struct.unpack('>H', client_data[:2])[0]
            current_time = time.time()

            tids_to_remove = [k for k, v in active_requests.items() if current_time - v > LOOP_TIMEOUT]
            for k in tids_to_remove:
                del active_requests[k]

            domain, q_type, q_class, question_length = client_request(client_data)
            type_name = QTYPES.get(q_type, str(q_type))

            remaining_ttl, cached_rdata = my_cache.get(domain, q_class, q_type)
            answer_type = q_type

            if cached_rdata is None and q_type != 5:
                remaining_ttl, cached_rdata = my_cache.get(domain, q_class, 5)
                if cached_rdata is not None:
                    answer_type = 5

            if cached_rdata is not None:

                print(f"{client_ip}, {type_name}, {domain}, cache")

                response_data = response_packet(client_data, question_length, answer_type, q_class, remaining_ttl,
                                                cached_rdata)
                server_socket.sendto(response_data, client_address)

            else:

                if tid in active_requests:
                    print(f"обнаружена петля")
                    continue

                active_requests[tid] = current_time

                forwarder_response = forwarder(client_data, args.forwarder)

                if forwarder_response is not None:
                    forward_parser(forwarder_response, my_cache)

                    _, new_rdata = my_cache.get(domain, q_class, q_type)

                    print(f"{client_ip}, {type_name}, {domain}, forwarder")

                    server_socket.sendto(forwarder_response, client_address)

                    del active_requests[tid]
                else:
                    pass # если форвардер не отвечает

        except Exception as e:
            print("\n=== ПРОИЗОШЛА ОШИБКА ===")
            import traceback

            traceback.print_exc()
            print("========================\n")
