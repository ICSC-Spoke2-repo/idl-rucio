FROM jupyter/tensorflow-notebook:ubuntu-22.04

#Copy from github wrapper.py and conda_rucio_env.yaml files
RUN git clone https://github.com/LucaPacioselli/Wrap-Env.git
#Extract the wrapper and the conda env files in the parent directory
RUN mv /home/jovyan/Wrap-Env/conda_rucio_env.yaml /home/jovyan/
RUN mv /home/jovyan/Wrap-Env/wrap.py /home/jovyan/

#Initialize conda
RUN conda init
RUN source ~/.bashrc

#Create environment with working rucio client 
RUN conda env create -f conda_rucio_env.yaml

#Create an empty rucio.cfg in /opt/conda/envs/temp-rucio-env/etc/
RUN echo "" > /opt/conda/envs/temp-rucio-env/etc/rucio.cfg

#RUN mkdir -p /opt/rucio/etc/
#RUN cd /opt/rucio/etc/
#RUN nano rucio.cfg

#Create a kernel from temp-rucio-env
RUN conda install ipykernel
RUN python3 -m ipykernel install --user --name rucio --display-name "RucioKernel"