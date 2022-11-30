FROM python:3.8-alpine as compile
WORKDIR /opt
RUN apk add --no-cache git gcc musl-dev python3-dev libffi-dev openssl-dev cargo
RUN python3 -m pip install virtualenv
RUN virtualenv -p python venv
ENV PATH="/opt/venv/bin:$PATH"
RUN git clone --depth 1 https://github.com/ly4k/Certipy.git
WORKDIR /opt/Certipy
RUN python3 setup.py install
RUN pip3 install pycryptodome

FROM python:3.8-alpine
COPY --from=compile /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
WORKDIR /opt/Certipy
ENTRYPOINT ["certipy"]