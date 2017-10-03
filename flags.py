from ryu import cfg
from os.path import expanduser

CONF = cfg.CONF
CONF.register_cli_opts([cfg.StrOpt('Groups',default='Group.conf',help='Group config file location'),cfg.StrOpt('SigFile',default='Group.sig',help='Group signature file location'),cfg.StrOpt('Key',default=expanduser("~")+"/.ssh/id_rsa.pub",help='public key for verifying the config file'),cfg.StrOpt('Rules',default='Rules.txt',help='iptables rules for the controller')])

