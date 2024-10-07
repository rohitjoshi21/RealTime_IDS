import subprocess

# change_dir = 'cd /mnt/WorkingDrive/Automated-Intrusion-Detection-System-'


activate_env = 'source /home/riemann/.cache/pypoetry/virtualenvs/cicflowmeter-J2zf1J8o-py3.11/bin/activate &&'
cmd = f'{activate_env} cicflowmeter -f nirajport.pcapng -c output.csv'
subprocess.run(cmd, shell=True, executable='/bin/bash')