from python:3

WORKDIR /app
COPY ./server.py ./server.py

ENTRYPOINT ["python3", "./server.py"]
