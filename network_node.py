import sys
import asyncio
import json
import hashlib
import time
from aioconsole import ainput
from concurrent.futures import ThreadPoolExecutor

ID = 0xabcdeeee
TARGET = 0x000000000000001fffffffffffffffffffffffffffffffffffffffffffffffff
c = 2**32
min = (11*c)//12
max = c - 1


def hash_256(data):
    return hashlib.sha256(bytes(json.dumps(data), encoding='utf-8')).digest().hex()


class Connection:
    def __init__(self, reader, writer):
        self.reader = reader
        self.writer = writer
        self.address = writer.get_extra_info('peername')


def node_print(msg):  # Beauty printing
    print("\r"+msg + "\nnode>> ", end="", flush=True)


class Node:
    def __init__(self, host, port):
        # Host y Port en donde va a correr el servidor
        self.host = host
        self.port = port
        # Host y Port del nodo al que se quiere conectar
        self.ref_host = None
        self.ref_port = None

        self.server = None
        self.connections = []  # Informacion de los nodos que se encuentran conectados a este

        self.version = 1
        genesis_block = {
            'type': 'block',
            'prev_block': '',
            'transactions': []
        }
        self.block_chain = [genesis_block]  # En el blockchain se referencia al ultimo
        self.tx_pool = []  # Un pool de transacciones conocidas que no se encuentran en el blockchain
        self.utxo = []
        self.miss_hashes = []

        self.sync_lock = False
        self.last_message = ''

        self.updated = True
        self.block_recieved = False

    '''
    ##############################################
        Connection handling
    ##############################################
    '''

    def run(self):
        # Obtener el loop de funciones asincornas
        loop = asyncio.get_event_loop()
        ex = ThreadPoolExecutor(2)
        # Crear el task que se encarga de el servidor
        server_task = loop.create_task(self.server_init(self.host, self.port))
        # Inicia la interfaz de interaccion con el nodo
        prompt_task = loop.create_task(self.prompt_init())
        # Inicia la tarea de minear bloques
        mining_task = loop.create_task(self.mining_thread())
        # mining_task = loop.run_in_executor(ex, self.mining_thread)
        # mining_task = ex.submit(self.mining_thread)
        # mining_task.result()
        # It never ends
        loop.run_forever()

    def save_connection(self, reader, writer):  # Genera el objeto de conexion para cada nodo conectado
        conn = Connection(reader, writer)
        self.connections.append(conn)
        node_print(f'Connected to {conn.address!r}')

    async def spread_signal(self, msg, excluded_addr=None):
        for conn in self.connections:
            if conn.address != excluded_addr:
                conn.writer.write(msg)
                await conn.writer.drain()

    async def send_signal(self, msg, addr):
        for conn in self.connections:
            if conn.address == addr:
                conn.writer.write(msg)
                await conn.writer.drain()
                break

    async def server_init(self, host, port):  # Inicia el servidor que acepta conexiones de nuevos nodos
        # Se inicia el servidor en la direccion (host,port)
        # Ejecuta la funcion handle_conection cuando recibe una nueva conexion
        self.server = await asyncio.start_server(self.handle_connection, host, port) 

        # Mostar que se inicio el servidor correctamente
        addr = self.server.sockets[0].getsockname()
        node_print(f'Serving on {addr}')

    async def handle_connection(self, reader, writer):
        # Guardar conexiones para ser usadas
        self.save_connection(reader, writer)
        addr = writer.get_extra_info('peername')
        # Mantenerse escuchando
        while True:
            data = await reader.read(2048)
            message = data.decode()
            if message == "":
                break
            await self.read_command(data, addr)

        node_print(f"Closed connection from {addr!r}")
        writer.close()

    async def new_connection(self, host, port):  # Inicia la conexion que le permite entrar a la red
        reader, writer = await asyncio.open_connection(host, port)
        loop = asyncio.get_event_loop()
        task = loop.create_task(self.handle_connection(reader, writer))
        writer.write(self.send_version())

    '''
    ##################################################
        Behaviour and Interaction
    ##################################################
    '''
    
    async def prompt_init(self):
        while True:
            prompt = await ainput("\rnode>> ")  # Input que no bloquea el resto de la ejecucion
            cmd = prompt.strip().split(' ')
            if cmd[0] == 'show':
                print(f'MSG: {self.last_message!r}')
            elif cmd[0] == 's':
                self.show()
            elif cmd[0] == 'c':
                if len(cmd) == 3:
                    host = cmd[1]
                    port = int(cmd[2])
                    await self.new_connection(host, port)
                else:
                    print("For new connection use command: c <host> <port>")
                
            elif cmd[0] == 't':
                value = cmd[1]
                await self.spread_signal(self.create_tx(value), None)
                print("Creating transaction")
            elif cmd[0] == 'b':
                await self.spread_signal(self.create_block(), None)
                print("Creating block")

    async def read_command(self, encode_message, addr):
        message = self.decode(encode_message)
        node_print(str(message))
        if 'command' not in message.keys():
            return
        command = message['command']
        payload = message['payload']
        if command == 0x00:
            await self.compare_version(payload, addr)
            return
        if command == 0x01:
            await self.send_signal(self.complete_hashes(payload), addr)
            return
        if command == 0x02:
            await self.complete_block_chain(payload, addr)
            return
        if command == 0x03:
            await self.send_signal(self.send_data(payload), addr)
            return
        if command == 0x04:
            await self.add_block(payload, addr)
            return
        if command == 0x05:
            verify_tx = list(filter(lambda tx: tx['id'] == payload['id'], self.tx_pool))
            if len(verify_tx) == 0:
                node_print("New tx recieved")
                await self.spread_signal(self.add_new_tx(payload), excluded_addr=addr)
            return
        if command == 0x06:
            verify_block = list(filter(lambda block: hash_256(block) == hash_256(payload), self.block_chain))
            if len(verify_block) == 0:
                node_print("New block recieved")
                self.block_recieved = True
                await self.spread_signal(self.add_new_block(payload), excluded_addr=addr)
            return


    '''
    ############################################
        Logic functions for commands
    ############################################
    '''
    async def compare_version(self, version, addr):
        if version < self.version:
            await self.send_signal(self.send_version(),addr)
        elif version == self.version:
            return 
        else:
            await self.send_signal(self.send_hashes(), addr)

    async def complete_block_chain(self, miss_hashes, addr):
        if len(miss_hashes) > 0:
            self.miss_hashes = miss_hashes
            next_hash = self.miss_hashes.pop(0)
            await self.send_signal(self.get_data(next_hash), addr)
        return

    async def add_block(self, block, addr):
        self.block_chain.append(block)
        self.version = len(self.block_chain)
        if len(self.miss_hashes) > 0:
            next_hash = self.miss_hashes.pop(0)
            await self.send_signal(self.get_data(next_hash), addr)
        return

    def add_new_tx(self, tx):
        self.tx_pool.append(tx)
        return self.create_msg(0x05, tx)

    def add_new_block(self, block):
        self.block_chain.append(block)
        self.tx_pool = []
        self.version = len(self.block_chain)
        return self.create_msg(0x06, block)

    # Set messages types
    def send_version(self):
        return self.create_msg(0x00, self.version)

    def send_hashes(self):
        hashes = []
        for block in self.block_chain:
            hashes.append(hash_256(block))
        return self.create_msg(0x01, hashes)

    def complete_hashes(self, hashes):
        miss_hashes = []
        for block in self.block_chain:
            if hash_256(block) not in hashes:
                miss_hashes.append(hash_256(block))
        return self.create_msg(0x02, miss_hashes)

    def get_data(self, hash_data):
        return self.create_msg(0x03, hash_data)

    def send_data(self, hash_data):
        search_block = None
        for block in self.block_chain:
            if hash_256(block) == hash_data:
                search_block = block
        return self.create_msg(0x04, search_block)

    def create_tx(self, value):
        tx = {
            'type': 'transaction',
            'id': '',
            'time': time.time(),
            'value': value
        }
        tx['id'] = hash_256(tx)
        self.tx_pool.append(tx)
        return self.create_msg(0x05, tx)

    def create_block(self):
        transactions = []
        for i in range(5):
            if len(self.tx_pool) > i:
                transactions.append(self.tx_pool[i])
            else:
                break
        if len(self.block_chain) == 0:
            block = {
                'type': 'block',
                'prev_block': '',
                'transactions': transactions
            }
        else:
            prev_block = self.block_chain[-1]
            block = {
                'type': 'block',
                'prev_block': hash_256(prev_block),
                'transactions': transactions
            }
        # self.tx_pool = []
        # block = self.mine_block(block)
        # self.block_chain.append(block)
        # self.version = len(self.block_chain)
        # return self.create_msg(0x06, block)
        return block

    async def mining_thread(self):
        while True:
            if self.updated:
                pre_block = self.create_block()
                # node_print("Mining start")
                block = await self.mine_block(pre_block) # Trata de encontra un nonce que cumpla con el target
                if block:
                    # Eliminar transacciones de pool
                    for tx in block['transactions']:
                        self.tx_pool.remove(tx)
                    # Añadir el bloque al blockchain
                    self.block_chain.append(block)
                    # Esparcir el bloque
                    await self.spread_signal(self.create_msg(0x06, block))
            await asyncio.sleep(0)


    async def mine_block(self, block):
        for nonce in range(min, max):
            if self.block_recieved or not self.updated:
                node_print("Mining Interrupted")
                self.block_recieved = False
                break
            block['nonce'] = nonce
            h = hash_256(block)
            int_h = int(h, 16)
            int_target = int(str(TARGET), 16)
            if int_h < int_target:
                node_print("Block Mined!!!")
                return block
            await asyncio.sleep(0)
        node_print("Mining Failed")
        return None

    def verify_block_chain(self):
        if len(self.block_chain) < 2:
            return
        first_block = self.block_chain[0]
        for block in self.block_chain[1:]:
            if block['prev_block'] == hash_256(first_block):
                print('True')
            first_block = block


    '''
    ###################################################
        Message Format
    ###################################################
    '''
    def create_msg(self, command, payload):
        message = {'command': command, 'payload': payload}
        return self.encode(message)

    def show(self):
        node_print("#####")
        node_print(f"version:{self.version}")
        node_print("Blockchain:")
        for block in self.block_chain:
            node_print(str(block))
        node_print("Transaction pool:")
        for tx in self.tx_pool:
            node_print(str(tx['id'])+ '-' + str(tx['value']))
        node_print("#####")
    # Function for bytes communication
    @staticmethod
    def decode(data):
        return json.loads(data.decode(encoding='utf-8'))

    @staticmethod
    def encode(data):
        return bytes(json.dumps(data), encoding='utf-8')


if __name__ == '__main__':
    argv = sys.argv
    try:
        if len(argv) == 3:
            host_param = argv[1]
            port_param = int(argv[2])
        else:
            host_param = 'localhost'
            port_param = 8888
        node = Node(host_param, port_param)
        node.run()
    except ValueError:
        print("Valid host and port were not provided, node will run in (localhost,8888)")
        node = Node('localhost', 8888)
        node.run()
