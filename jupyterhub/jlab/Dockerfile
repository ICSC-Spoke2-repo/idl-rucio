FROM jupyter/scipy-notebook:x86_64-ubuntu-22.04

USER $NB_UID

RUN conda install -y -c conda-forge python-gfal2 \
    && conda clean --all -f -y

RUN /opt/conda/bin/python3 -m pip install rucio-jupyterlab==1.2.1 \
    && jupyter serverextension enable --py rucio_jupyterlab --sys-prefix

USER root

# To make sure that appending the rucio-jlab config to the already existing .json doesn't create an invalid JSON file
RUN apt-get update && apt-get install -y jq

# NodeJS v>=20 (needed by rucio-jupyterlab)
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
RUN sudo apt-get install -y nodejs

RUN apt update -y \
    && apt install -y build-essential \
    && apt install -y curl \
    && apt install -y voms-clients-java software-properties-common \
    && apt clean -y

RUN /opt/conda/bin/python3 -m pip install ipykernel

# Setup extension Rucio instance config
ADD ./jupyterhub/jlab/configure.py /opt/setup/configure.py
ADD ./jupyterhub/jlab/setup.sh /usr/local/bin/setup.sh
RUN fix-permissions /opt/setup \
    && fix-permissions /usr/local/bin/setup.sh \
    && sed -i -e 's/\r$/\n/' /usr/local/bin/setup.sh \
    && chmod +x /usr/local/bin/setup.sh

ENV RUCIO_MODE=download
ENV RUCIO_WILDCARD_ENABLED=1
ENV RUCIO_BASE_URL=https://rucio-server.212.189.145.208.myip.cloud.infn.it
ENV RUCIO_AUTH_URL=https://rucio-server.212.189.145.208.myip.cloud.infn.it
ENV RUCIO_WEBUI_URL=https://webui.212.189.145.208.myip.cloud.infn.it
ENV RUCIO_DISPLAY_NAME="IDL Test Extension"
ENV RUCIO_NAME=IDL
ENV RUCIO_CA_CERT=/etc/ssl/certs/ca-certificates.crt

RUN mkdir -p /opt/rucio \
    && chown -R $NB_UID /opt/rucio \
    && /usr/local/bin/setup.sh \
    && chown -R $NB_UID /etc/jupyter/jupyter_notebook_config.json 

ENV IPYTHONDIR=/etc/ipython
ADD ./jupyterhub/jlab/ipython_kernel_config.json /etc/ipython/profile_default/ipython_kernel_config.json
RUN chown -R $NB_UID /etc/ipython
ENV JUPYTER_ENABLE_LAB=yes

# https warnings
RUN /opt/conda/bin/python3 -m pip install urllib3

# Install specific version of rucio-clients using system pip
RUN /opt/conda/bin/python3 -m pip install rucio-clients==35.6.1

# To use the system Python executable and rucio-clients in the system's /usr/local/bin/
ENV PATH="/usr/local/bin:${PATH}"

# Install the package for rucio commands autocompletion
RUN /opt/conda/bin/python3 -m pip install argcomplete 

# Copy files in the image because I can move them as root from the Dockerfile
COPY ./client-test/IDL /usr/local/bin/IDL
RUN chmod 555 /usr/local/bin/IDL
COPY ./jupyterhub/jlab/cred.py /usr/local/bin/cred.py
RUN chmod 555 /usr/local/bin/cred.py

RUN jupyter lab build

WORKDIR $HOME
USER $NB_UID

CMD ["setup.sh", "start-notebook.sh"]