# imagem base oficial do Python (slim para menor tamanho)
FROM python:3.11-slim

# diretorio de trabalho dentro do container
WORKDIR /app

# copia o arquivo de dependencias primeiro para aproveitar cache do Docker
COPY requirements.txt .

# instala as dependencias
RUN pip install --no-cache-dir -r requirements.txt

# copia os arquivos necessarios
COPY grpc_client_docker.py .
COPY sensor.proto .
COPY multicast_config.py .
COPY server_public.pem .

# copia os arquivos py gerados pelo protoc
COPY sensor_pb2.py .
COPY sensor_pb2_grpc.py .

# gerar gRPC dentro do build
# RUN python -m grpc_tools.protoc -I. --python_out=. --grpc_python_out=. sensor.proto

# comando para executar o cliente
CMD ["python", "-u", "grpc_client_docker.py"]