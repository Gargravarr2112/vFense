FROM rethinkdb
COPY . /opt/vFense-Server
WORKDIR /opt/vFense-Server
ENV PYTHONUSERBASE=/opt/vFense-Server/venv-deb
ENV PYTHONPATH /opt/vFense-Server/lib:${PYTHONUSERBASE}/lib/python3.4/site-packages/
ENV DEBIAN_FRONTEND=noninteractive
RUN sed -i -e s#://deb.debian.org#://cdn-fastly.deb.debian.org# /etc/apt/sources.list \
    && echo "Acquire::http::Proxy \"http://192.168.1.4:8000\";" > /etc/apt/apt.conf.d/30proxy \
    && apt-get update
RUN apt-get install ---yes python3-pip python3-pkg-resources python-virtualenv python-apt libssl-dev python-beautifulsoup python3-bcrypt python3-tornado python3-redis python3-requests python3-setuptools python3-cryptography python3-openssl libffi-dev libxml2-dev libxslt-dev
RUN pip3 install --user --requirement /opt/vFense-Server/pip-requirements.txt \
    && apt-get clean
RUN python3 /opt/vFense-Server/lib/vFense/scripts/initialize_vFense.py
