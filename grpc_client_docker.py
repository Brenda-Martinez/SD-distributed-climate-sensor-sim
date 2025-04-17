import grpc
import time
import os
import sys
import logging
import threading
import collections
from collections import OrderedDict
import uuid
import json
import sensor_pb2
import sensor_pb2_grpc
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature

# config logging
LOG_FORMAT = '%(asctime)s [ClienteDocker-%(threadName)s] %(levelname)s: %(message)s'
logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)
logger = logging.getLogger("ClientDockerLogger")
logger.setLevel(logging.INFO)

POLL_INTERVAL = 10
SNAPSHOT_INTERVAL_CYCLES = 3
CLIENT_CHECKPOINT_HISTORY_SIZE = 5
CLIENT_CHECKPOINT_DIR = "checkpoints_client"  # salva dentro do container
CLIENT_CHECKPOINT_FILENAME_PREFIX = "checkpoint_client_"
CLIENT_ID_FILENAME = "client_id.txt"  # salva dentro do container
SERVER_PUBLIC_KEY_FILE = "server_public.pem"

HOST_IP = '192.168.1.13'

# lista de sensores que o cliente tentara contatar (devem estar ativos no HOST)
MANUAL_SENSORS = {
    "sensor_cl_01": {"host": HOST_IP, "port": 65400},
    "sensor_cl_02": {"host": HOST_IP, "port": 65401},
    "sensor_cl_03": {"host": HOST_IP, "port": 65402},
}

# Estado Global do Cliente
CLIENT_ID = None  # definido no inicio
client_lamport_clock = 0; client_lock = threading.Lock()
# dicionario p guardar estado da sessao por sensor
# { sensor_id: {"token": str, "aes_key": bytes, "established_at": ts} ou None }
sensor_sessions = {}; session_lock = threading.Lock()
# estado de snapshot e historico
current_snapshot_data = None; snapshot_lock = threading.Lock(); active_snapshot_id = -1
verbose_mode = False; stop_event = threading.Event()
historical_data = collections.deque(maxlen=CLIENT_CHECKPOINT_HISTORY_SIZE)
server_public_key = None # chave publica carregada do servidor

def get_persistent_client_id(filename=CLIENT_ID_FILENAME):
    # carrega/gera e salva um ID de cliente persistente dentro do container
    client_id = None
    try:
        if os.path.exists(filename):
            with open(filename, 'r') as f: client_id = f.read().strip()
            if client_id: logger.debug(f"ID Cliente carregado de {filename}: {client_id}")
            else: logger.warning(f"{filename} vazio. Gerando novo."); client_id = None
        if not client_id:
            client_id = f"client_{uuid.uuid4().hex[:6]}"
            logger.info(f"Gerado novo ID Cliente: {client_id}. Salvando em {filename}")
            try:
                with open(filename, 'w') as f: f.write(client_id)
            except IOError as e: logger.error(f"Erro ao salvar ID: {e}")
    except Exception as e:
        logger.error(f"Erro ao obter ou gerar ID: {e}. Gerando ID temporario.")
        if not client_id: client_id = f"client_{uuid.uuid4().hex[:6]}_temp"
    return client_id


def update_client_clock(received_lc=None):
    global client_lamport_clock;
    with client_lock:
        if received_lc is not None: client_lamport_clock = max(client_lamport_clock, received_lc) + 1
        else: client_lamport_clock += 1;
        logger.debug(f"Clock logico do cliente (LC): {client_lamport_clock}"); return client_lamport_clock


def load_server_public_key(filename=SERVER_PUBLIC_KEY_FILE):
    # carrega a chave publica RSA do servidor do arquivo PEM
    try:
        with open(filename, "rb") as key_file: public_key = serialization.load_pem_public_key(key_file.read(), backend=default_backend())
        logger.info(f"Chave publica do servidor carregada de {filename}")
        return public_key
    except FileNotFoundError: logger.error(f"ERRO CRITICO: Arquivo da chave publica do servidor '{filename}' nao encontrado no container.")
    except Exception as e: logger.error(f"Falha ao carregar chave publica servidor {filename}: {e}")
    return None


def encrypt_with_rsa(public_key, data):
    # criptografa dados usando chave publica RSA (OAEP)
    try: return public_key.encrypt(data, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    except Exception as e: logger.error(f"Falha criptografia RSA: {e}"); return None


def decrypt_with_aes_gcm(key, iv, ciphertext, tag, associated_data=None):
    # descriptografa os dados usando AES-GCM, verificando a tag
    try:
        # cria o decifrador AES no modo GCM, passando o IV e a TAG recebidos para verificacao
        decryptor = Cipher(
            algorithms.AES(key),
            modes.GCM(iv, tag),  # fornece a tag para verificacao durante finalize()
            backend=default_backend()
        ).decryptor()

        # autentica dados adicionais antes de descriptografar
        if associated_data:
            decryptor.authenticate_additional_data(associated_data)

        # descriptografa os dados
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return plaintext

    # captura falha na verificacao da tag
    except InvalidSignature:
        logger.error("Falha ao descriptografar AES-GCM: tag de autenticacao invalida!")
        return None

    except Exception as e:
        logger.error(f"Falha ao descriptografar AES-GCM: {e}", exc_info=True)
        return None


# funcoes gRPC
def establish_session_with_sensor(sensor_id, host, port):
    # tenta estabelecer uma sessao AES segura com o sensor
    global server_public_key, CLIENT_ID, sensor_sessions, session_lock
    target = f"{host}:{port}"; logger.info(f"Tentando estabelecer sessao segura com {sensor_id}@{target}...")
    if not server_public_key: logger.error("Chave publica do servidor nao carregada."); return None
    try:
        with grpc.insecure_channel(target) as channel:
            stub = sensor_pb2_grpc.SensorServiceStub(channel); aes_key = os.urandom(32); iv_dummy = os.urandom(16); key_bundle = aes_key + iv_dummy
            encrypted_bundle = encrypt_with_rsa(server_public_key, key_bundle)
            if not encrypted_bundle: logger.error(f"Falha ao criptografar bundle p/ {sensor_id}"); return None
            request = sensor_pb2.EncryptedSessionKeyRequest( client_id=CLIENT_ID, encrypted_key_bundle=encrypted_bundle )
            response = stub.EstablishSession(request, timeout=7)
            if response and response.success and response.session_token:
                session_info = { "token": response.session_token, "aes_key": aes_key, "established_at": time.time() }
                logger.info(f"Sessao segura estabelecida com {sensor_id}. Token: {response.session_token[:8]}...")
                with session_lock: sensor_sessions[sensor_id] = session_info # Guarda a sessao
                return session_info
            else: logger.error(f"Falha ao estabelecer sessao com {sensor_id}: {response.message if response else 'Sem resposta'}"); return None
    except grpc.RpcError as e: logger.error(f"Erro gRPC [EstablishSession] com {sensor_id}@{target}: {e.code()}"); return None  # nao marca como falho, apenas falha sessao
    except Exception as e: logger.error(f"Erro inesperado [EstablishSession] com {sensor_id}@{target}: {e}"); return None


def get_sensor_data_grpc(sensor_id, host, port):
    # obtem os dados criptografados, estabelecendo sessao
    global sensor_sessions, session_lock  # usa o dict de sessoes
    target = f"{host}:{port}"; session_info = None; data_dict = None; needs_new_session = False

    with session_lock: session_info = sensor_sessions.get(sensor_id)
    if not session_info: needs_new_session = True

    if needs_new_session:
        session_info = establish_session_with_sensor(sensor_id, host, port)
        if not session_info: logger.error(f"Nao foi possivel estabelecer sessao com {sensor_id}."); return None

    logger.debug(f"Usando sessao {session_info['token'][:8]} p/ GetData de {sensor_id}@{target}")
    try:
        with grpc.insecure_channel(target) as channel:
            stub = sensor_pb2_grpc.SensorServiceStub(channel)
            request = sensor_pb2.SensorRequest(sensor_id_requested=sensor_id, session_token=session_info['token'])
            response = stub.GetData(request, timeout=5)  # resposta tem payload criptografado

            decrypted_payload_bytes = decrypt_with_aes_gcm( key=session_info['aes_key'], iv=response.iv, ciphertext=response.encrypted_payload, tag=response.auth_tag)
            if decrypted_payload_bytes:
                try:
                    decrypted_data = json.loads(decrypted_payload_bytes.decode('utf-8'))
                    current_client_lc = update_client_clock(response.lamport_timestamp)
                    logger.info(f"LC:{current_client_lc} - Dados DESCRIPTOGRAFADOS de {response.sensor_id}@{target} (LC:{response.lamport_timestamp}): T={decrypted_data.get('t'):.1f}°, U={decrypted_data.get('u'):.1f}%, P={decrypted_data.get('p'):.1f} ATM")
                    data_dict = { "sensor_id": response.sensor_id, "timestamp": decrypted_data.get('ts'), "temperatura": decrypted_data.get('t'), "umidade": decrypted_data.get('u'), "pressao": decrypted_data.get('p'), "lamport_timestamp": response.lamport_timestamp }
                    if response.sensor_id != sensor_id: logger.warning(f"ID recebido ({response.sensor_id}) diferente do esperado ({sensor_id})!")
                except (json.JSONDecodeError, KeyError) as e: logger.error(f"Erro ao processar payload descriptografado de {sensor_id}: {e}"); data_dict = None
            else: logger.error(f"Falha ao descriptografar dados de {sensor_id}."); data_dict = None
    except grpc.RpcError as e:
        logger.error(f"Erro gRPC [GetData] {sensor_id}@{target}: {e.code()}")
        if e.code() == grpc.StatusCode.UNAUTHENTICATED: logger.warning(f"Erro de autenticacao com {sensor_id}. Resetando sessao...");
        with session_lock: sensor_sessions.pop(sensor_id, None) # Remove sessao invalida
        return None
    except Exception as e: logger.error(f"Erro inesperado [GetData] {sensor_id}@{target}: {e}");
    with session_lock: sensor_sessions.pop(sensor_id, None); return None
    return data_dict


def send_marker_to_sensor(sensor_id, host, port, snapshot_id):
    target = f"{host}:{port}"; ack_marker_result = None; logger.debug(f"[Snapshot ID:{snapshot_id}] Enviando Marker (INSEGURO) p/ {sensor_id}@{target}...")
    try:
        with grpc.insecure_channel(target) as channel: stub = sensor_pb2_grpc.SensorServiceStub(channel); marker_lc = update_client_clock(); marker_to_send = sensor_pb2.SnapshotMarker( snapshot_id=snapshot_id, initiator_id=CLIENT_ID, source_id=CLIENT_ID, sender_lamport_clock=marker_lc, is_ack=False ); ack_marker_result = stub.ProcessMarker(marker_to_send, timeout=7); received_ack_lc = ack_marker_result.sender_lamport_clock; current_client_lc_after_ack = update_client_clock(received_ack_lc); logger.debug(f"[Snapshot ID:{snapshot_id}] Recebido ACK de {ack_marker_result.source_id} (LC:{received_ack_lc}). Cliente LC:{current_client_lc_after_ack}");
    except grpc.RpcError as e: logger.error(f"[Snapshot ID:{snapshot_id}] Erro gRPC [ProcessMarker] {sensor_id}@{target}: {e.code()}"); return {"error": f"gRPC Error: {e.code()}"}
    except Exception as e: logger.error(f"[Snapshot ID:{snapshot_id}] Erro inesperado [ProcessMarker] {sensor_id}@{target}: {e}"); return {"error": f"Unexpected Error: {e}"}
    return ack_marker_result


def initiate_chandy_lamport_snapshot(current_sensors_map):
    global current_snapshot_data, active_snapshot_id, client_lamport_clock;
    sensors_to_snapshot = current_sensors_map  # usa o mapa passado
    if not sensors_to_snapshot: logger.warning("Nenhum sensor configurado p snapshot."); return
    with snapshot_lock:
        if active_snapshot_id != -1: logger.warning(f"Snapshot {active_snapshot_id} ja ativo."); return
        current_lc = update_client_clock(); snapshot_id = time.time_ns(); active_snapshot_id = snapshot_id; logger.info(f"*** INICIANDO Snapshot CL (ID: {snapshot_id}, LC: {current_lc}) p/ {len(sensors_to_snapshot)} sensores ***")
        client_state = {"lamport_clock": current_lc}; snapshot_results = OrderedDict(); snapshot_results[CLIENT_ID] = {"state": client_state, "is_initiator": True}; pending_acks = set(sensors_to_snapshot.keys())
        for sensor_id, sensor_info in sensors_to_snapshot.items(): host = sensor_info['host']; port = sensor_info['port']; ack_result = send_marker_to_sensor(sensor_id, host, port, snapshot_id)
        if isinstance(ack_result, sensor_pb2.SnapshotMarker):
            if ack_result.HasField("recorded_state"): state = ack_result.recorded_state; snapshot_results[state.sensor_id] = { "state_lamport_clock": state.state_lamport_clock, "last_timestamp_physical": state.last_timestamp_physical, "last_temperatura": state.last_temperatura, "last_umidade": state.last_umidade, "last_pressao": state.last_pressao, "ack_received_lc": client_lamport_clock }; logger.debug(f"  -> Estado de {state.sensor_id} (LC:{state.state_lamport_clock}) adicionado.")
            else: snapshot_results[ack_result.source_id] = { "ack_only": True, "ack_lamport_clock": ack_result.sender_lamport_clock }; logger.warning(f"  -> ACK de {ack_result.source_id} sem estado.")
            if ack_result.source_id in pending_acks: pending_acks.remove(ack_result.source_id)
            else: logger.warning(f"ACK para {ack_result.source_id} nao pendente?")
        elif isinstance(ack_result, dict) and "error" in ack_result: snapshot_results[sensor_id] = ack_result;
        if sensor_id in pending_acks: pending_acks.remove(sensor_id)
        else: logger.error(f"Resultado inesperado de send_marker para {sensor_id}");
        if sensor_id in pending_acks: pending_acks.remove(sensor_id)
        time.sleep(0.1)
        final_lc = update_client_clock(); logger.info(f"*** SNAPSHOT CL CONCLUIDO (ID: {snapshot_id}, LC final: {final_lc}) ***")
        if pending_acks: logger.warning(f"Snapshot concluido, ACKs pendentes de: {pending_acks}")
        logger.debug("*** Conteudo do Snapshot Chandy-Lamport ***");  # restante do log do snapshot em DEBUG
        for node_id, data in snapshot_results.items():
             log_line = f"  No: {node_id} | ";
             if "error" in data: log_line += f"Erro: {data['error']}"
             elif node_id == CLIENT_ID: log_line += f"Estado Cliente: LC={data['state']['lamport_clock']}"
             elif "ack_only" in data: log_line += f"ACK s/ estado: SensorLC={data['ack_lamport_clock']}"
             else: phys_time_str="N/A"; ts = data.get('last_timestamp_physical');
             if ts: phys_time_str = time.strftime('%H:%M:%S', time.localtime(ts)); log_line += (f"Estado Sensor: LC={data['state_lamport_clock']} | Leitura ({phys_time_str}): T={data.get('last_temperatura','N/A'):.1f}, U={data.get('last_umidade','N/A'):.1f}, P={data.get('last_pressao','N/A'):.1f} | (Cliente LC no ACK: {data.get('ack_received_lc','N/A')})")
             logger.debug(log_line)
        logger.debug("----------------------------------------------------\n")
        current_snapshot_data = snapshot_results; active_snapshot_id = -1


def toggle_verbose_mode():
    global verbose_mode; verbose_mode = not verbose_mode; new_level = logging.DEBUG if verbose_mode else logging.INFO; logger.setLevel(new_level)
    print(f"\n*** Modo Verbose {'ATIVADO (DEBUG)' if verbose_mode else 'DESATIVADO (INFO)'} ***"); logger.info(f"Nivel log alterado: {logging.getLevelName(new_level)}")


# Thread para interacao do usuario
def user_input_thread():
    global stop_event; time.sleep(1); print("\n-------------------------------------------"); print("Comandos: 'v' (Verbose) | 'q' (Sair)"); print("-------------------------------------------")
    while not stop_event.is_set():
        try: command = input("Comando: ").strip().lower()
        except EOFError: logger.info("EOF recebido. Encerrando."); stop_event.set(); break
        except Exception as e: logger.error(f"Erro input usuario: {e}"); stop_event.set(); break
        if command == 'v': toggle_verbose_mode()
        elif command == 'q': logger.info("Comando 'q' recebido. Saindo..."); stop_event.set(); break
    logger.info("Thread de input finalizada.")


# checkpoint do cliente
def save_client_checkpoint(clock_value, history_deque):
    global CLIENT_ID; state_to_save = { 'client_lamport_clock': clock_value, 'data_history': list(history_deque) }
    if CLIENT_CHECKPOINT_DIR and not os.path.exists(CLIENT_CHECKPOINT_DIR):
        try: os.makedirs(CLIENT_CHECKPOINT_DIR)
        except OSError as e: logger.error(f"Erro ao criar dir chkpt cliente {CLIENT_CHECKPOINT_DIR}: {e}"); return
    filename = f"{CLIENT_CHECKPOINT_FILENAME_PREFIX}{CLIENT_ID}.json"; filepath = os.path.join(CLIENT_CHECKPOINT_DIR, filename) if CLIENT_CHECKPOINT_DIR else filename; tmp_filepath = filepath + ".tmp"; logger.debug(f"Salvando checkpoint do cliente em {filepath}...")
    try:
        with open(tmp_filepath, 'w') as f: json.dump(state_to_save, f, indent=4); os.replace(tmp_filepath, filepath); logger.debug(f"Checkpoint do cliente salvo.")
    except Exception as e: logger.error(f"Erro ao salvar o checkpoint do cliente {filepath}: {e}", exc_info=True)
    if os.path.exists(tmp_filepath):
            try: os.remove(tmp_filepath)
            except OSError: pass


def load_client_checkpoint(history_deque):
    global client_lamport_clock, CLIENT_ID; filename = f"{CLIENT_CHECKPOINT_FILENAME_PREFIX}{CLIENT_ID}.json"; filepath = os.path.join(CLIENT_CHECKPOINT_DIR, filename) if CLIENT_CHECKPOINT_DIR else filename
    if not os.path.exists(filepath): logger.info(f"Checkpoint nao encontrado: {filepath}"); return False
    logger.info(f"Carregando checkpoint de {filepath}...")
    try:
        with open(filepath, 'r') as f: loaded_state = json.load(f);
        with client_lock: client_lamport_clock = loaded_state.get('client_lamport_clock', 0)
        loaded_history = loaded_state.get('data_history', []); history_deque.clear(); history_deque.extend(loaded_history); logger.info(f"Estado cliente restaurado (LC={client_lamport_clock}, Historico={len(history_deque)}).")
        print("\n*** DADOS RESTAURADOS DO CHECKPOINT ***")
        if not history_deque: print("  (Nenhum historico)")
        else:
            for i, cycle_data in enumerate(history_deque): cycle_ts = cycle_data.get('cycle_timestamp', 0); cycle_time_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(cycle_ts)) if cycle_ts else "N/A"; print(f" Ciclo #{i+1} ({cycle_time_str}):")
            sensor_readings = cycle_data.get('sensor_readings', {})
            if not sensor_readings: print("    (Sem leituras)")
            else:
                for sensor_id, data in sensor_readings.items(): phys_ts = data.get('timestamp', 0); phys_time_str = time.strftime('%H:%M:%S', time.localtime(phys_ts)) if phys_ts else 'N/A'; print(f"    {sensor_id}: T={data.get('temperatura','N/A'):.1f}, U={data.get('umidade','N/A'):.1f}, P={data.get('pressao','N/A'):.1f} (LC_S: {data.get('lamport_timestamp','N/A')}, TS_F: {phys_time_str})")
        print("----------------------------------------\n")
        logger.debug(f"Historico restaurado: {list(history_deque)}"); return True
    except (json.JSONDecodeError, KeyError, Exception) as e: logger.error(f"Erro ao carregar checkpoint {filepath}: {e}", exc_info=True);
    with client_lock: client_lamport_clock = 0; history_deque.clear(); return False


# Main Loop do Cliente
if __name__ == "__main__":
    # obtem ou gera o ID persistente
    CLIENT_ID = get_persistent_client_id()
    if not CLIENT_ID: sys.exit("ERRO FATAL: Nao foi possivel obter/gerar ID do cliente.")

    # carrega a chave publica do servidor
    server_public_key = load_server_public_key()
    if not server_public_key:
        logger.critical(f"Nao foi possivel carregar chave publica ({SERVER_PUBLIC_KEY_FILE}). Encerrando cliente...")
        sys.exit(1)

    threading.current_thread().name = "MainThread"
    logger.info(f"Cliente Docker [ID: {CLIENT_ID}] iniciado.")
    logger.info(f"Modo Verbose Inicial: {'ATIVADO' if verbose_mode else 'DESATIVADO'}")

    # tenta carregar checkpoint
    load_client_checkpoint(historical_data)

    # inicia thread de interacao do usuario
    input_thread = threading.Thread(target=user_input_thread, daemon=True, name="UserInputThread")
    input_thread.start()

    # nao inicia listener multicast nesta versao
    logger.info(f"Aguardando inicio do polling (Sensores em {HOST_IP})...")
    time.sleep(3)  # curta pausa inicial

    polling_cycle_count = 0
    try:
        # loop principal usando a lista MANUAL_SENSORS
        while not stop_event.is_set():
            polling_cycle_count += 1
            current_lc = update_client_clock()
            logger.debug(f"[ Ciclo Polling #{polling_cycle_count} | Cliente LC: {current_lc} ]")

            # usa a lista manual de sensores
            current_sensors_to_poll = MANUAL_SENSORS.copy()  # copia o dict dos sensores

            results_this_cycle = {'cycle_timestamp': time.time(), 'sensor_readings': {}}
            active_count_in_cycle = 0  # contador para sensores ativos no ciclo

            if not current_sensors_to_poll: logger.warning("Nenhum sensor configurado.")
            else:
                 logger.debug(f"Sensores configurados p/ polling: {list(current_sensors_to_poll.keys())}")

                 # inicia snapshot
                 if polling_cycle_count % SNAPSHOT_INTERVAL_CYCLES == 0:
                     logger.warning("Snapshot iniciado sobre sensores configurados.")
                     initiate_chandy_lamport_snapshot(current_sensors_to_poll)  # passa mapa correto
                     current_lc = update_client_clock(); logger.debug(f"*** Retornando ao polling (LC: {current_lc}) ***")

                 # coleta dados usando get_sensor_data_grpc seguro
                 logger.info(f"Iniciando coleta de dados dos {len(current_sensors_to_poll)} sensores configurados...")
                 successful_reads = 0

                 # itera sobre a lista de sensores
                 for sensor_id, sensor_info in current_sensors_to_poll.items():
                     logger.debug(f"Tentando sensor {sensor_id}...")
                     # tenta obter sessao e dados descriptografados
                     sensor_data_dict = get_sensor_data_grpc(sensor_id, sensor_info['host'], sensor_info['port'])
                     if sensor_data_dict is not None:
                         successful_reads += 1
                         results_this_cycle['sensor_readings'][sensor_id] = sensor_data_dict  # armazena dict descriptografado
                         active_count_in_cycle += 1  # conta como ativo se respondeu
                     # else: O get_sensor_data_grpc ja loga o erro
                     if stop_event.is_set(): break
                     sys.stdout.flush(); time.sleep(0.1)  # flush e pausa
                 if stop_event.is_set(): break
                 # log do resumo da coleta em INFO
                 logger.info(f"Coleta concluida ({successful_reads}/{len(current_sensors_to_poll)} sensores responderam).")
                 if results_this_cycle['sensor_readings']: historical_data.append(results_this_cycle); logger.debug(f"Resultados adicionados ao historico ({len(historical_data)}).")

            # salva checkpoint do cliente
            save_client_checkpoint(client_lamport_clock, historical_data)

            logger.debug(f"*** [ Ciclo Polling #{polling_cycle_count} Concluido | Cliente LC: {client_lamport_clock} ] ***")
            logger.debug(f"Aguardando {POLL_INTERVAL} segundos...")
            stop_event.wait(POLL_INTERVAL)

    except KeyboardInterrupt: logger.info("\nCtrl+C recebido. Sinalizando para sair..."); stop_event.set()
    finally: logger.info("Cliente Encerrado."); time.sleep(0.5)