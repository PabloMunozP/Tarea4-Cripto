import os,time,bcrypt

path_output=os.path.join(os.getcwd(),'outputs')
path_hashcat= os.path.join(os.getcwd(),'hashcat-6.1.1')
path_hashes=os.path.join(os.getcwd(),'Hashes')
path_dict=os.path.join(os.getcwd(),'diccionarios')

def opciones_crackear():
    #elegir el archivo de hash
    opcion_hash=input('Ingrese el numero del archivo a crackear: ')
    while opcion_hash not in ['1','2','3','4','5']:
        opcion_hash=input('Ingrese el numero del archivo a crackear: ')
    hash_file=os.path.join(path_hashes,'archivo_'+str(opcion_hash))
    #elegir el diccionario
    opcion_dict=input('Ingrese el numero del diccionario: ')
    while opcion_dict not in ['1','2']:
        opcion_dict=input('Ingrese el numero del diccionario: ')
    dict_file=os.path.join(path_dict,'diccionario_'+str(opcion_dict)+'.dict')
    #configurar el output
    print('\nEl archivo de salida sera guardado en la carpeta outputs con el nombre Archivo_X_Dict_Y, con X e Y los numeros de los archivos elegidos.\n')
    output_file=os.path.join(path_output,'Archivo_'+str(opcion_hash)+'_Dict_'+str(opcion_dict))
    
    salida=open(output_file,'w')#crear el archivo de salida
    salida.close()
    crackear(hash_file,dict_file,output_file)


def crackear(archivo,diccionario,output_name='output.txt'):
    try:
        cmd='hashcat.exe'

        if os.name != 'nt':
            cmd=cmd.replace('\\','/')

        output=str(os.path.join(path_output,output_name))
        if os.path.exists(output):
            os.remove(output)
        
        print('''
            Modos 
            1->0
            2->10
            3->10
            4->0
            5->1800
            ''')
        hash_mode=input('Ingrese el modo del hash a crackear: ')
        while hash_mode.isnumeric() is not True:
            hash_mode=input('Ingrese el modo del hash a crackear: ')

        cmd+=' -m'+str(hash_mode)+' -a0 '+archivo+' '+diccionario+' --outfile='+output
        os.chdir(path_hashcat)

        try:
            os.remove('hashcat.potfile')
        except:
            pass
        
        #print(os.getcwd(),'\n',cmd)
        start=time.time()
        os.system(cmd)
        os.remove('hashcat.potfile')
        stop=time.time()
        tiempos=open(os.path.join(path_output,'tiempos.txt'),'a')
        line ='Archivo: '+archivo+'\n Diccionario: '+ diccionario+'\nTiempo de inicio: '+ str(start)+ '\nTiempo de fin: '+str(stop)+'\nTiempo total: '+ str(stop-start)+'\n----------------------------------\n'
        tiempos.write(line)

        #se crea el archivo con las contraseñas encontradas
        path_pwd=get_pwds(output)
        print('Las contraseñas crakeadas se encuentran en: ', path_pwd )

    except Exception as e:
        print('Error: ', str(e))



def get_pwds(output):
    try:
        input_file=open(output,'r')
        output_file=open(os.path.join(path_output,'pwds'),'a')#se agregan las nuevas contraseñas al archivo de salida
        

        for line in input_file:
            line=line.strip()
            output_data=list(line.split(':'))[-1]
            output_file.write(output_data+'\n')
        
        output_file.close()

        return os.path.join(path_output,'pwds')

    except Exception as e:
        print('Error: ',str(e))


def hashear():




def menu():
    print('''Tarea 4 Pablo Muñoz Poblete
        1- Crackear contraseñas mediante
        2- Hashear contraseñas en texto plano
        3- Salir
     ''')



if __name__ == "__main__":
    try:
        while True:
            menu()
            opcion=input('Ingrese la opcion deseada: ')
            while opcion not in ['1','2','3']:
                opcion=input('Ingrese la opcion deseada: ')
            if opcion == '1':
                opciones_crackear()
            if opcion == '2':
                pass
            if opcion == '3':
                exit()
    except KeyboardInterrupt:
        exit()