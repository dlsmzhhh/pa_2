import pathlib
import socket
import sys
import time
from datetime import datetime
import secrets
import traceback

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from numpy import byte


def convert_int_to_bytes(x):
    """
    Convenience function to convert Python integers to a length-8 byte representation
    """
    return x.to_bytes(8, "big")


def convert_bytes_to_int(xbytes):
    """
    Convenience function to convert byte value to integer value
    """
    return int.from_bytes(xbytes, "big")


def read_bytes(socket, length):
    """
    Reads the specified length of bytes from the given socket and returns a bytestring
    """
    buffer = []
    bytes_received = 0
    while bytes_received < length:
        data = socket.recv(min(length - bytes_received, 1024))
        if not data:
            raise Exception("Socket connection broken")
        buffer.append(data)
        bytes_received += len(data)

    return b"".join(buffer)


def main(args):
    port = int(args[0]) if len(args) > 0 else 4321
    address = args[1] if len(args) > 1 else "localhost"


    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((address, port))
            s.listen()

            client_socket, client_address = s.accept()
            with client_socket:
                while True:
                    match convert_bytes_to_int(read_bytes(client_socket, 8)):
                        case 0:
                            # If the packet is for transferring the filename
                            print("Receiving file...")
                            filename_len = convert_bytes_to_int(
                                read_bytes(client_socket, 8)
                            )
                            filename = read_bytes(
                                client_socket, filename_len
                            ).decode("utf-8")
                            # print(filename)
                        case 1:
                            # If the packet is for transferring a chunk of the file
                            start_time = time.time()

                            file_len = convert_bytes_to_int(
                                read_bytes(client_socket, 8)
                            )

                            # read and decrypt data
                            data_encrypted = read_bytes(client_socket, file_len)
                            file_data = session_key.decrypt(data_encrypted)

                            with open(f"recv_files_enc/enc_recv_{filename.split('/')[-1]}", mode="wb") as fout:
                                fout.write(data_encrypted)
                                
                            
                            # print(file_data)

                            filename = "recv_" + filename.split("/")[-1]

                            # Write the file with 'recv_' prefix
                            with open(
                                f"recv_files/{filename}", mode="wb"
                            ) as fp:
                                fp.write(file_data)
                            print(
                                f"Finished receiving file in {(time.time() - start_time)}s!"
                            )
                        case 2:
                            # Close the connection
                            # Python context used here so no need to explicitly close the socket
                            print("Closing connection...")
                            s.close()
                            # break
                        case 3:
                            message_len = convert_bytes_to_int(
                                read_bytes(client_socket, 8)
                            )
                            message = read_bytes(client_socket, message_len)
                            
                            # signed message
                            try:
                                with open("auth/server_private_key.pem", mode="r", encoding="utf8") as key_file:
                                    private_key = serialization.load_pem_private_key(
                                        bytes(key_file.read(), encoding="utf8"), password=None
                                    )
                            except Exception as e:
                                print(e)

                            signed_message = private_key.sign(
                                                message, # message in bytes format
                                                padding.PSS(
                                                    mgf=padding.MGF1(hashes.SHA256()),
                                                    salt_length=padding.PSS.MAX_LENGTH,
                                                ),
                                                hashes.SHA256(), # hashing algorithm used to hash the data before encryption
                                            )

                            # how to send?
                            client_socket.sendall(convert_int_to_bytes(len(signed_message)))
                            client_socket.sendall(signed_message)
                        

                            # send M2 server_signed.crt
                            with open("auth/server_signed.crt", mode="rb") as fp:
                                data = fp.read()
                                client_socket.sendall(convert_int_to_bytes(len(data)))
                                client_socket.sendall(data)
                        
                        case 4:
                            key_part_one_len = convert_bytes_to_int(read_bytes(client_socket, 8))
                            key_part_one = private_key.decrypt(
                                read_bytes(client_socket, key_part_one_len),
                                padding.OAEP(
                                    mgf=padding.MGF1(hashes.SHA256()),
                                        algorithm=hashes.SHA256(),
                                        label=None,
                                ),
                            )
                            
                            key_part_two_len = convert_bytes_to_int(read_bytes(client_socket, 8))
                            key_part_two = private_key.decrypt(
                                read_bytes(client_socket, key_part_two_len),
                                padding.OAEP(
                                    mgf=padding.MGF1(hashes.SHA256()),
                                        algorithm=hashes.SHA256(),
                                        label=None,
                                ),
                            )

                            key_part_three_len = convert_bytes_to_int(read_bytes(client_socket, 8))
                            key_part_three = private_key.decrypt(
                                read_bytes(client_socket, key_part_three_len),
                                padding.OAEP(
                                    mgf=padding.MGF1(hashes.SHA256()),
                                        algorithm=hashes.SHA256(),
                                        label=None,
                                ),
                            )

                            session_key_bytes = key_part_one + key_part_two + key_part_three
                            session_key = Fernet(session_key_bytes)


    except Exception as e:
        print(e)
        s.close()


if __name__ == "__main__":
    main(sys.argv[1:])
