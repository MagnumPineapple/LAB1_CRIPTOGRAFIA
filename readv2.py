import pyshark
import sys
from termcolor import colored

def read_pcap(file_name):
    cap = pyshark.FileCapture(file_name, display_filter='icmp')
    data_strings = []

    for packet in cap:
        try:
            if packet.icmp.type == '8':  # Solo considera paquetes ICMP Request (tipo 8)
                icmp_data = packet.icmp.data
                # Decodificación dependiente de cómo estés codificando los datos en el envío
                decoded_data = bytes.fromhex(icmp_data).decode('utf-8')
                data_strings.append(decoded_data)
        except AttributeError as e:
            # print(f"Omitiendo paquete debido a un error: {e}")
            continue

    return ''.join(data_strings)


def cesar_decipher(text, shift):
    decrypted_text = ''
    
    for char in text:
        if char.isalpha():
            shifted = ord(char) - shift
            if char.islower():
                if shifted < ord('a'):
                    shifted += 26
                decrypted_text += chr(shifted)
            elif char.isupper():
                if shifted < ord('A'):
                    shifted += 26
                decrypted_text += chr(shifted)
        else:
            decrypted_text += char
    return decrypted_text

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Uso: python3 readv2.py [nombre_archivo.pcapng]")
        sys.exit(1)
        
    file_name = sys.argv[1]
    extracted_data = read_pcap(file_name)

    if not extracted_data:
        print("No se han encontrado paquetes ICMP Request en el archivo.")
        sys.exit(1)

    for shift in range(26):
        decrypted_text = cesar_decipher(extracted_data, shift)
        if shift == 9:  # El corrimiento más probable es 9
            print(colored(f"{shift}     {decrypted_text}", "green"))
        else:
            print(f"{shift}     {decrypted_text}")


