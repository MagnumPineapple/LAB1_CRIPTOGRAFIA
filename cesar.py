import sys

def cesar_cipher(text, shift):
    encrypted_text = ''
    
    for char in text:
        if char.isalpha():
            shifted = ord(char) + shift
            if char.islower():
                if shifted > ord('z'):
                    shifted -= 26
                encrypted_text += chr(shifted)
            elif char.isupper():
                if shifted > ord('Z'):
                    shifted -= 26
                encrypted_text += chr(shifted)
        else:
            encrypted_text += char
    
    return encrypted_text

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Uso: python3 cesar.py [texto] [desplazamiento]")
    else:
        text = sys.argv[1]
        shift = int(sys.argv[2])
        
        encrypted_text = cesar_cipher(text, shift)
        print(encrypted_text)

