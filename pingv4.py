from scapy.all import *
import sys
import time

def send_icmp_data(data, destination_ip='8.8.8.8'):
    identification = 0x1234
    icmp_id = 0x5678
    seq_number = 0
    
    # Enviando un ping real para comparación
    print("Sending real ICMP request for comparison...")
    real_ping = IP(dst=destination_ip, id=identification)/ICMP(id=icmp_id, seq=seq_number)
    send(real_ping)
    real_ping.show()

    for i, char in enumerate(data):
        seq_number += 1
        print(f"Sending character: {char}")

        hex_char = char.encode().hex()
        timestamp = int(time.time())  # Aquí generamos el timestamp
        payload = '08 00' + ' ' + ' '.join(hex(timestamp)[2:].zfill(8))  # Lo añadimos al payload
        payload += ' ' + hex_char + ' ' + '00' * (48 - len(payload) // 3)
        
        custom_packet = IP(dst=destination_ip, id=identification)/ICMP(id=icmp_id, seq=seq_number)/Raw(load=bytes.fromhex(payload.replace(' ', '')))
        send(custom_packet)
        print("Sent 1 packet.")
        time.sleep(0.5)

    # Enviando otro ping real para comparación
    seq_number += 1
    print("Sending another real ICMP request for comparison...")
    real_ping = IP(dst=destination_ip, id=identification)/ICMP(id=icmp_id, seq=seq_number)
    send(real_ping)
    real_ping.show()

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: sudo python3 pingv4.py [encrypted_text]")
        sys.exit(1)

    encrypted_text = sys.argv[1]
    print(f"Encrypted text: {encrypted_text}")
    send_icmp_data(encrypted_text)
