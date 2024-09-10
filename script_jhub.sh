#!/bin/bash

#Initialize Conda
conda init

#Ensure .bash_profile sources .bashrc
echo -e "if [ -f ~/.bashrc ]; then\n\tsource ~/.bashrc\nfi" > ~/.bash_profile

#Add Conda activate command to .bashrc if not already present
#grep -qxF "conda activate temp-rucio-env" ~/.bashrc || echo -e "conda activate temp-rucio-env\n\n" >> ~/.bashrc

#Add path to /usr/bin/ to locate wrap.py from anywhere if not already present
grep -qxF "export PATH=$PATH:/usr/bin" ~/.bashrc || echo -e "export PATH=$PATH:/usr/bin\n\n" >> ~/.bashrc


#Check if the warning is already present
if ! grep -q 'WARNING: The server may have restarted.' ~/.bashrc; then
    #Append the warning to .bashrc
    echo '# Print reminder to update the rucio.cfg file' >> ~/.bashrc
    echo 'echo "********************************************************************"' >> ~/.bashrc
    echo 'echo "* WARNING: The server may have restarted.                          *"' >> ~/.bashrc
    echo 'echo "* If the output of rucio whoami is not shown at the startup of a   *"' >> ~/.bashrc
    echo 'echo "* new terminal, please edit the                                    *"' >> ~/.bashrc
    echo 'echo "* /opt/conda/envs/temp-rucio-env/etc/rucio.cfg                     *"' >> ~/.bashrc
    echo 'echo "* with the cred.py script, e.g.:                                   *"' >> ~/.bashrc
    echo 'echo "* """cred.py --user <USERNAME> --a <ACCOUNT>                       *"' >> ~/.bashrc
    echo 'echo "* Enter the password (hidden): <PASSWORD>                          *"' >> ~/.bashrc
    echo 'echo "* Updated 'rucio.cfg' -> username, password, account correctly"""  *"' >> ~/.bashrc
    echo -e 'echo "*****************************************************************"\n\n' >> ~/.bashrc
#    echo -e "conda deactivate\nconda activate temp-rucio-env" >> ~/.bashrc
fi

source ~/.bashrc

# Check if the kernel already exists
if ! jupyter kernelspec list | grep -q rucio; then
    #echo "Kernel 'rucio' does not exist. Creating it now..."
    
    # Install the kernel using ipykernel
    conda activate temp-rucio-env
    python3 -m ipykernel install --user --name "rucio" --display-name "RucioKernel"
fi

grep -qxF "conda deactivate" ~/.bashrc || echo -e "conda deactivate\nconda activate temp-rucio-env" >> ~/.bashrc

source ~/.bashrc

eval "$(register-python-argcomplete rucio)"
rucio whoami
