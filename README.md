# SD-distributed-climate-sensor-sim
Sistema distribuído completo que simula uma plataforma de  consulta e monitoramento de sensores climáticos remotos, utilizando os principais  conceitos e técnicas de sistemas distribuídos.
## Como executar o sistema (local)
### Servidor
1. Abra o CMD (Windows)
2. Vá até o local do projeto com o comando cd "LOCAL DO PROJETO"
3. Execute o seguinte comando: python grpc_sensor_server.py --id {id_do_sensor} --port {porta_da_rede}
4. Repita os passos 1 - 3 para cada sensor que será monitorado
### Cliente
1. Abra o CMD (Windows)
2. Vá até o local do projeto com o comando cd "LOCAL DO PROJETO"
3. Execute o seguinte comando: python grpc_client.py

## Como executar o sistema (Docker - Nuvem Simulada)
### Servidor - Executado localmente
1. Abra o CMD (Windows)
2. Vá até o local do projeto com o comando cd "LOCAL DO PROJETO"
3. Execute o seguinte comando: python grpc_sensor_server.py --id {id_do_sensor} --port {porta_da_rede}
4. Repita os passos 1 - 3 para cada sensor que será monitorado
### Cliente
1. Abra o CMD (Windows)
2. Vá até o local do projeto com o comando cd "LOCAL DO PROJETO"
3. Construa a imagem docker com o comando: docker build -t sensor-client-app .
4. Execute o container com o comando: docker run --rm -it sensor-client-app
