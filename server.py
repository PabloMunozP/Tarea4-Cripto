import BG,socket,os,sqlite3,pickle

path_outputs = os.path.join(os.getcwd(),'outputs')

def connect_db(db_file):
    conn=None
    try:
        conn = sqlite3.connect(db_file)
    except Exception as e:
        print('Error: ',e)
    
    return conn

def create_table(conn,table_statement):
    try:
        cursor=conn.cursor()
        cursor.execute(table_statement)
    except Exception as e:
        print('Error:',e)

def insert(conn,id,hash):
    try:
        insert_statement='''INSERT INTO hashes(id,hash) VALUES(?,?);'''
        cursor= conn.cursor()
        cursor.execute(insert_statement,(id,hash))
        conn.commit()
    except Exception as e:
        print('Error:',e)

def delete(db,delete_statement):
    cursor=db.cursor()
    cursor.execute(delete_statement)
    db.commit()

s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.bind((socket.gethostname(),3214))
s.listen(3)

#este envia la llave publica y desencripta 



if __name__ == "__main__":
    cliente,direccion = s.accept()
    print(f'Se ha establecido conexion desde {direccion}\nListo para enviar llave publica\n')
    p,q=499,547
    key=BG.key_generation(p,q)
    cliente.sendall(bytes(str(key),'utf-8'))
    print('Se envio la clave publica\n')
    db=connect_db(os.path.join(path_outputs,'sqlite_db.db'))
       
    table_statement='''CREATE TABLE IF NOT EXISTS hashes(
         id integer PRIMARY KEY,
         hash text NOT NULL); '''
    delete_statement='''DROP TABLE hashes;''' 
    if db:
        try:
            delete(db,delete_statement)
        except:
            pass
        create_table(db,table_statement)
    else:
        print('Error al crear la DB')
    
    counter=1
    HEADERSIZE=10
    full_msg=b''
    new_msg=True
    counter=1
    while True:
        msg=cliente.recv(4096)
        if new_msg:
            msglen=int(msg[:HEADERSIZE])
            new_msg=False
        full_msg+= msg

        if len(full_msg)-HEADERSIZE == msglen:
            encrypted = pickle.loads(full_msg[HEADERSIZE:])
            print("mensaje cifrado:", encrypted)
            decrypted = BG.decrypt(p,q,encrypted)
            decrypted=BG.bin_toAscii(decrypted)
            print("mensaje descifrado (ASCII):",decrypted)
            insert(db,counter,decrypted)
            cliente.send("ok".encode())
            counter+=1
            new_msg = True
            full_msg = b""

    