# Ollama Chatbot Client
Demo of an Ollama Chatbot Client.
<P>
OllamaClientService exposes prompt1() or prompt2(), to forward a Prompt to an ollama instance and receive a response.
<P>
OllamaClientService uses the Ollama client from Spring AI framework.
<P>
OllamaClientServiceIT contains Junit 5 tests to exercise OllamaClientService. 

## Quickstart
Starting an ollama container is the quickest and easiest way to get an ollama instance.

```bash
docker run --rm -d -v ollama:/root/.ollama --network=ollama -p 11434:11434 --name ollama ollama/ollama:latest
```
Notes:
1. The above command uses `ollama` volume to persist ollama models downloaded in `/root/.ollama/`. Delete the volume if you want to revert to no ollama models.
2. Inside the container, Ollama's HTTP API listens to 0.0.0.0:11434
3. Inside the container, you can use HTTP base URL http://localhost:11434 in your REST API clients (e.g. curl).
4. Outside the container, you can use HTTP base URL http://localhost:11434 in your REST API clients (e.g. OllamaClientService, web browser, curl, postman, etc).

## Useful Docker commands

### Docker Setup
```bash
docker ps -a
docker image ls
docker volume list
docker network list
docker pull ollama/ollama:latest
docker volume create ollama
docker network create ollama
``` 

### Docker Cleanup
```bash
docker stop ollama
docker rm ollama
docker volume rm ollama
docker network rm ollama
docker image rm ollama/ollama:latest
```

## Useful Ollama commands

### Examples of how to download a model to /root/.ollama/
```bash
docker exec -it ollama ollama pull mistral
docker exec -it ollama ollama pull llama3.2
docker exec -it ollama ollama pull gemma2
docker exec -it ollama ollama pull phi3
docker exec -it ollama ollama pull llava
```
Notes:
1. mistral is from Mistral AI
2. llama3.2 is from Meta
2. gemma2 is from Google
3. phi3 and llava are from Microsoft

### Examples of how to load a model into memory from /root/.ollama/
```bash
docker exec -it ollama ollama run mistral
docker exec -it ollama ollama run llama3.2
docker exec -it ollama ollama run llava
docker exec -it ollama ollama run gemma2
```

## Useful Ubuntu base container commands

### Upgrade Ubuntu
```bash
docker exec -it ollama bash -c 'apt-get update && apt-get -y upgrade'
```

### Install useful utilities
```bash
docker exec -it ollama bash -c 'apt-get update && apt-get install -y curl net-tools iputils-ping nmap vim'
```

### Shell access
```bash
docker exec -it ollama bash
```

## Useful Ollama API calls
Detailed API docs are available at https://github.com/ollama/ollama/blob/main/docs/api.md

### Curl Examples

```bash
apt-get update && apt-get install -y curl

curl -i GET http://localhost:11434/
curl -i GET http://localhost:11434/api/version
curl -i GET http://localhost:11434/api/tags
curl -i GET http://localhost:11434/api/ps
curl -i POST http://localhost:11434/api/generate -d '{
  "model": "llama3.2",
  "prompt": "Why is the sky blue?",
  "stream": false,
  "options": {
    "temperature": 0.9
  }
}'
curl http://localhost:11434/api/chat -d '{
  "model": "llama3.2",
  "messages": [
    { "role": "system", "content": "You are a good assistant, and you talk like a pirate." },
    { "role": "user", "content": "Why is the sky blue?" }
  ],
  "stream": false,
  "options": {
    "temperature": 0.9
  }
}'
```

