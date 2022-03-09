FROM python:3.9-slim-buster

COPY ./Certipy/ /app 
WORKDIR /app

RUN python3 setup.py install
ENTRYPOINT ["certipy"]





