import BG,socket,os,sqlite3

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

def insert(conn,id,hash_ascii,hash_bin):
    try:
        insert_statement='''INSERT INTO hashes(id,hash_ascii,hash_bin) VALUES(?,?,?);'''
        cursor= conn.cursor()
        cursor.execute(insert_statement,(id,hash_ascii,hash_bin))
        conn.commit()
    except Exception as e:
        print('Error:',e)

s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.bind((socket.gethostname(),3214))
s.listen(3)

#este envia la llave publica y desencripta 
while True:
    cliente,direccion = s.accept()
    print(f'Se ha establecido conexion desde {direccion}\nListo para enviar llave publica\n')
    p,q=499,547
    key=BG.key_generation(p,q)
    cliente.sendall(bytes(str(key),'utf-8'))
    print('Se envio la clave publica\n')
    path=cliente.recv(1024).decode('utf-8')
    #print(path)
    print('Se ha recibido el archivo.\nSe inicia el proceso de desencriptacion.\n')
    output=open(path,'r')
    db=connect_db(os.path.join(path_outputs,'sqlite_db.db'))
       
    table_statement='''CREATE TABLE IF NOT EXISTS hashes(
         id integer PRIMARY KEY,
         hash_ascii text NOT NULL,
         hash_bin text NOT NULL); ''' 

    if db is not None:
        create_table(db,table_statement)
    else:
        print('Error al crear la DB')
    
    counter=1
    for line in output:
        if line == '\n':
            break
        line=line.strip()
        encrypted=line.split(',')
        #print(counter,'  ',len(encrypted))
        decrypted=BG.decrypt(p,q,encrypted)
        insert(db,counter,BG.bin_toAscii(decrypted),decrypted)
        counter+=1
    print('Finalizo la desencriptacion y se guardaron los hash en un archivo sqlite.\n')

    