FROM python:3

WORKDIR /app
COPY ./server.py ./server.py

STOPSIGNAL SIGTERM
ENTRYPOINT ["python3", "./server.py"]
