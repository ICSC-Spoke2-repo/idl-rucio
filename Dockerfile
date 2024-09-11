FROM jupyter/tensorflow-notebook:ubuntu-22.04
#datascience-notebook:x86_64-ubuntu-22.04

#Because in k8s /home/jovyan is built by the provisioner and you cannot keep anything there at the start
WORKDIR /opt/conda/

#Copy from github wrapper.py and conda_rucio_env.yaml files
RUN git clone https://github.com/LucaPacioselli/Wrap-Env.git
WORKDIR /opt/conda/Wrap-Env/
#RUN ls -R
#Extract the wrapper and the conda env files in the parent directory
#RUN mv /opt/conda/Wrap-Env/conda_rucio_env.yaml /opt/conda/
#RUN mv /opt/conda/Wrap-Env/script_jhub.sh /opt/conda/
#Root otherwise you can't write to /usr/bin
USER root
RUN mv /opt/conda/Wrap-Env/wrap.py /usr/bin/
RUN mv /opt/conda/Wrap-Env/cred.py /usr/bin/
RUN chmod a+x /usr/bin/wrap.py
RUN chmod a+x /usr/bin/cred.py
RUN chmod a+x /opt/conda/Wrap-Env/script_jhub.sh
#RUN rm -r Wrap-Env


#RUN conda init
#RUN source ~/.bashrc

##.bashrc is a non-login shell, to make conda init work when opening a new terminal you need to edit .bash_profile 
#RUN echo \
#"if [ -f ~/.bashrc ]; then \
#    source ~/.bashrc \
#fi" > ~/.bash_profile


#WORKDIR /opt/conda/ 

#Initialize conda
SHELL ["/bin/bash", "-c"]
RUN source /opt/conda/etc/profile.d/conda.sh && \
    conda init

#.bashrc is a non-login shell, to make conda init work when opening a new terminal we need to edit .bash_profile 
RUN source ~/.bashrc
RUN echo \
"if [ -f ~/.bashrc ]; then \
    source ~/.bashrc \
fi" > ~/.bash_profile

#Install Rucio JLab extension with some dependencies
USER root
#NodeJS v>=20
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
RUN sudo apt-get install -y nodejs
RUN pip3 install rucio-jupyterlab
RUN sudo apt-get install -y voms-clients-java
RUN pip3 install --upgrade jupyterlab

#Create environment with working rucio client 
RUN conda env create -f conda_rucio_env.yaml
RUN source /opt/conda/etc/profile.d/conda.sh && \
    conda activate temp-rucio-env

#Install ipykernel to create a kernel for the notebook
#RUN source /opt/conda/etc/profile.d/conda.sh && \
#    conda install ipykernel
#RUN python3 -m ipykernel install --user --name rucio --display-name "RucioKernel"

RUN mv /opt/conda/Wrap-Env/rucio.cfg /opt/conda/envs/temp-rucio-env/etc/
RUN chmod a+w /opt/conda/envs/temp-rucio-env/etc/rucio.cfg

##Set temp-rucio-env as default env
#WORKDIR /home/
#RUN echo "conda activate temp-rucio-env" >> /home/.bashrc
#RUN source /home/.bashrc

#Create an empty rucio.cfg in /opt/conda/envs/temp-rucio-env/etc/ if it doesn't already exist
#RUN [ ! -f /opt/conda/envs/temp-rucio-env/etc/rucio.cfg ] && touch /opt/conda/envs/temp-rucio-env/etc/rucio.cfg || echo "rucio.cfg already exists"
#RUN echo "" > /opt/conda/envs/temp-rucio-env/etc/rucio.cfg
#RUN chmod a+w /opt/conda/envs/temp-rucio-env/etc/rucio.cfg

#RUN mkdir -p /opt/rucio/etc/
#RUN cd /opt/rucio/etc/
#RUN nano rucio.cfg

#Create a kernel from temp-rucio-env
#RUN conda run -n temp-rucio-env
#RUN conda install ipykernel
#RUN python3 -m ipykernel install --user --name rucio --display-name "RucioKernel"

WORKDIR /home/jovyan