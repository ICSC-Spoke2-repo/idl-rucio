FROM jupyter/tensorflow-notebook:ubuntu-22.04

# Because in k8s /home/jovyan is built by the provisioner and you cannot keep anything there at the start
WORKDIR /opt/conda/

# Initialize conda
SHELL ["/bin/bash", "-c"]
RUN source /opt/conda/etc/profile.d/conda.sh && \
    conda init

# Install Rucio JLab extension with some dependencies
USER root

# To make sure that appending the rucio-jlab config to the already existing .json doesn't create an invalid JSON file
RUN apt-get update && apt-get install -y jq

# NodeJS v>=20 (needed by rucio-jupyterlab)
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
RUN sudo apt-get install -y nodejs

# JupyterLab extension for rucio in download mode and dependencies
RUN pip3 install rucio-jupyterlab
RUN sudo apt-get install -y voms-clients-java
RUN conda install conda-forge::python-gfal2
RUN conda install conda-forge::gfal2-util
RUN pip3 install --upgrade jupyterlab
RUN pip install ksmm
RUN pip install urllib3

# Install the rucio client
RUN pip3 install rucio-clients

# Install the package for rucio commands autocompletion
RUN pip3 install argcomplete 

# Copy files in the image because I can move them as root from the Dockerfile
COPY ./script_jhub.sh /opt/conda/script_jhub.sh
RUN chmod a+x /opt/conda/script_jhub.sh
COPY ./IDL /usr/bin/IDL
RUN chmod a+x /usr/bin/IDL
COPY ./cred.py /usr/bin/cred.py
RUN chmod a+x /usr/bin/cred.py

RUN mkdir /opt/conda/rt-kernels/

COPY ./rt-6-34-kernel.json /opt/conda/rt-kernels/rt-6-34-kernel.json

RUN jupyter kernelspec install /opt/conda/rt-kernels/ --prefix=/usr/local/

RUN jupyter lab build

WORKDIR /home/jovyan/