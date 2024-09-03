FROM jupyter/tensorflow-notebook:ubuntu-22.04

WORKDIR /home/jovyan

#Copy from github wrapper.py and conda_rucio_env.yaml files
RUN git clone https://github.com/LucaPacioselli/Wrap-Env.git
#Extract the wrapper and the conda env files in the parent directory
RUN mv /home/jovyan/Wrap-Env/conda_rucio_env.yaml /home/jovyan/
RUN mv /home/jovyan/Wrap-Env/wrap.py /home/jovyan/
RUN rm -r Wrap-Env

#Initialize conda
RUN conda init
RUN source ~/.bashrc

#.bashrc is a non-login shell, to make conda init work when opening a new terminal you need to edit .bash_profile 
RUN echo \
"if [ -f ~/.bashrc ]; then \
    source ~/.bashrc \
fi" > .bash_profile

#Create environment with working rucio client 
RUN conda env create -f conda_rucio_env.yaml

#Set temp-rucio-env as default env
RUN echo "conda activate temp-rucio-env" >> .bashrc
RUN source ~/.bashrc

#Create an empty rucio.cfg in /opt/conda/envs/temp-rucio-env/etc/
RUN echo "" > /opt/conda/envs/temp-rucio-env/etc/rucio.cfg

#RUN mkdir -p /opt/rucio/etc/
#RUN cd /opt/rucio/etc/
#RUN nano rucio.cfg

#Create a kernel from temp-rucio-env
RUN conda run -n temp-rucio-env
RUN conda install ipykernel
RUN python3 -m ipykernel install --user --name rucio --display-name "RucioKernel"