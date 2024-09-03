FROM jupyter/tensorflow-notebook:ubuntu-22.04

#Because in k8s /home/jovyan is built by the provisioner and you cannot keep anything there at the start
WORKDIR /opt/conda/

#Copy from github wrapper.py and conda_rucio_env.yaml files
RUN git clone https://github.com/LucaPacioselli/Wrap-Env.git
#Extract the wrapper and the conda env files in the parent directory
RUN mv /opt/conda/Wrap-Env/conda_rucio_env.yaml /opt/conda/
RUN mv /opt/conda/Wrap-Env/post-start-script-jhub.sh /opt/conda/
#Root otherwise you can't write to /usr/bin
USER root
RUN mv /opt/conda/Wrap-Env/wrap.py /usr/bin/
RUN chmod a+x /usr/bin/wrap.py
RUN chmod +x /opt/conda/post-start-script-jhub.sh
RUN rm -r Wrap-Env

#Initialize conda
#RUN conda init
#RUN source ~/.bashrc

##.bashrc is a non-login shell, to make conda init work when opening a new terminal you need to edit .bash_profile 
#RUN echo \
#"if [ -f ~/.bashrc ]; then \
#    source ~/.bashrc \
#fi" > ~/.bash_profile

#Create environment with working rucio client 
#WORKDIR /opt/conda/ 
SHELL ["/bin/bash", "-c"]
RUN source /opt/conda/etc/profile.d/conda.sh && \
    conda init
RUN source ~/.bashrc
RUN echo \
"if [ -f ~/.bashrc ]; then \
    source ~/.bashrc \
fi" > ~/.bash_profile
RUN conda env create -f conda_rucio_env.yaml
RUN source /opt/conda/etc/profile.d/conda.sh && \
    conda activate temp-rucio-env
RUN source /opt/conda/etc/profile.d/conda.sh && \
    conda install ipykernel
RUN python3 -m ipykernel install --user --name rucio --display-name "RucioKernel"

##Set temp-rucio-env as default env
#WORKDIR /home/
#RUN echo "conda activate temp-rucio-env" >> /home/.bashrc
#RUN source /home/.bashrc

#Create an empty rucio.cfg in /opt/conda/envs/temp-rucio-env/etc/
RUN echo "" > /opt/conda/envs/temp-rucio-env/etc/rucio.cfg
RUN chmod a+w /opt/conda/envs/temp-rucio-env/etc/rucio.cfg

#RUN mkdir -p /opt/rucio/etc/
#RUN cd /opt/rucio/etc/
#RUN nano rucio.cfg

#Create a kernel from temp-rucio-env
#RUN conda run -n temp-rucio-env
#RUN conda install ipykernel
#RUN python3 -m ipykernel install --user --name rucio --display-name "RucioKernel"

WORKDIR /home/jovyan