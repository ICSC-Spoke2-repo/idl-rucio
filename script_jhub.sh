#!/bin/bash

#Initialize Conda
conda init

#Create profile_default if it doesn't exist and run the command to create it
if [ ! -d "/home/jovyan/.ipython/profile_default" ]; then
    ipython profile create default 
fi

#Move the config files in the correct location
if [ ! -f "/opt/conda/etc/rucio.cfg" ]; then
    cp /home/jovyan/idl_configs/rucio.cfg /opt/conda/etc/rucio.cfg
fi

#if ! grep -q 'export IPYTHONDIR=/home/jovyan/ipython_kernel_config.py' ~/.bashrc; then
#    echo "export IPYTHONDIR=/home/jovyan/ipython_kernel_config.py" >> ~/.bashrc
#fi

#if ! grep -q 'export JUPYTER_CONFIG_DIR=/home/jovyan/jupyter_notebook_config.json' ~/.bashrc; then
#    echo "export JUPYTER_CONFIG_DIR=/home/jovyan/jupyter_notebook_config.json" >> ~/.bashrc
#fi

chmod +r /home/jovyan/idl_configs/jupyter_notebook_config.json
chown -R jovyan:users /home/jovyan/.jupyter
chown -R jovyan:users /home/jovyan/idl_configs/

if [ ! -f "/home/jovyan/.jupyter/jupyter_notebook_config.json" ]; then
    cp /home/jovyan/idl_configs/jupyter_notebook_config.json /home/jovyan/.jupyter/jupyter_notebook_config.json
fi

#Old string and replacement string
search_string="# c.IPKernelApp.extensions = \[\]"
replace_string="c.IPKernelApp.extensions = \['rucio_jupyterlab.kernels.ipython'\]"

#Check if the search string exists in the file
if grep -q "$search_string" "/home/jovyan/.ipython/profile_default/ipython_kernel_config.py"; then
    sed -i "s|$search_string|$replace_string|g" "/home/jovyan/.ipython/profile_default/ipython_kernel_config.py"
fi

#Ensure .bash_profile sources .bashrc
echo -e "if [ -f ~/.bashrc ]; then\n\tsource ~/.bashrc\nfi" > ~/.bash_profile

#Add path to /usr/bin/ to locate idl_cli and cred.py from anywhere if not already present
grep -qxF "export PATH=$PATH:/usr/bin" ~/.bashrc || echo -e "export PATH=$PATH:/usr/bin\n\n" >> ~/.bashrc

#Check if the warning is already present
if ! grep -q 'WARNING: The server may have restarted.' ~/.bashrc; then
    #Append the warning to .bashrc
    echo '# Print reminder to update the rucio.cfg file' >> ~/.bashrc
    echo 'echo "********************************************************************"' >> ~/.bashrc
    echo 'echo "* WARNING: The server may have restarted.                          *"' >> ~/.bashrc
    echo 'echo "* If the output of rucio whoami is not shown at the startup of a   *"' >> ~/.bashrc
    echo 'echo "* new terminal, please edit the                                    *"' >> ~/.bashrc
    echo 'echo "* /opt/conda/etc/rucio.cfg                                         *"' >> ~/.bashrc
    echo 'echo "* with the cred.py script, e.g.:                                   *"' >> ~/.bashrc
    echo 'echo "* cred.py --user <USERNAME> --account <ACCOUNT>                    *"' >> ~/.bashrc
    echo 'echo "* Enter the password (hidden): <PASSWORD>                          *"' >> ~/.bashrc
    echo 'echo "* Updated 'rucio.cfg' -> username, password, account correctly       *"' >> ~/.bashrc
    echo -e 'echo "********************************************************************"\n\n' >> ~/.bashrc
#    echo -e "conda deactivate\nconda activate temp-rucio-env" >> ~/.bashrc
fi

source ~/.bashrc

# Check if the kernel already exists
#if ! jupyter kernelspec list | grep -q rucio; then
    #echo "Kernel 'rucio' does not exist. Creating it now..."
    
    # Install the kernel using ipykernel
#    conda activate temp-rucio-env
#    python3 -m ipykernel install --user --name "rucio" --display-name "RucioKernel"
#fi

#grep -qxF "conda deactivate" ~/.bashrc || echo -e "conda deactivate\nconda activate temp-rucio-env" >> ~/.bashrc

#source ~/.bashrc

grep -qxF 'eval "$(register-python-argcomplete rucio)"' ~/.bashrc || echo -e 'eval "$(register-python-argcomplete rucio)"' >> ~/.bashrc
grep -qxF 'eval "$(register-python-argcomplete idl_cli)"' ~/.bashrc || echo -e 'eval "$(register-python-argcomplete idl_cli)"' >> ~/.bashrc
grep -qxF 'eval "$(register-python-argcomplete cred.py)"' ~/.bashrc || echo -e 'eval "$(register-python-argcomplete cred.py)"' >> ~/.bashrc
grep -qxF "rucio whoami" ~/.bashrc || echo -e 'rucio whoami' >> ~/.bashrc