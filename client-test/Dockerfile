FROM rucio/rucio-clients:release-35.6.1

USER root

RUN pip install numpy

# Rucio.cfg template for IDL
COPY ./client-test/rucio.cfg /opt/rucio/etc/rucio.cfg

# Custom client for IDL
COPY ./client-test/IDL /usr/local/bin/IDL
RUN chmod 555 /usr/local/bin/IDL

# Script to edit username, password and account of the rucio.cfg file
COPY ./jupyterhub/jlab/cred.py /usr/local/bin/cred.py
RUN chmod 555 /usr/local/bin/cred.py
