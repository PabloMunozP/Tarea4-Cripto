import BG,socket

s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.bind((socket.gethostname(),3030))
s.listen(3)

#este desencripta recibiendo la clave publica
while True:
    cliente,direccion = s.accept()
    print(f'Se ha establecido conexion desde {direccion}\n Listo para recibir la clave publica\n')
    public_key = cliente.recv(1024).decode('utf-8')
    print(public_key)
    if public_key is not None:
        print('La llave publica es: ',public_key)
    
