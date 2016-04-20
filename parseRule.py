import os
import iptc

def initDic():
    d = {}
    d['-m'] = ''
    d['-p'] = ''
    d['-src-range'] = ''
    d['-dst-range'] = ''
    d['-sport'] = ''
    d['-dport'] = ''
    d['-j'] = ''
    return d

def createRule(cmdDic):
    rule = iptc.Rule()
    if cmdDic['-p'] != '':
        rule.protocol = cmdDic['-p']
        match = iptc.Match(rule, cmdDic['-p'])
        if cmdDic['-dport'] != '':
            match.dport = cmdDic['-dport']
        if cmdDic['-sport'] != '':
            match.sport = cmdDic['-sport']
        rule.add_match(match)
    if cmdDic['-m'] != '':
        match = iptc.Match(rule, cmdDic['-m'])
        if cmdDic['-src-range'] != '':
            match.src_range = cmdDic['-src-range']
        if cmdDic['-dst-range'] != '':
            match.dst_range = cmdDic['-dst-range']
        rule.add_match(match)
    if cmdDic['-j'] != '':
        rule.target = iptc.Target(rule, cmdDic['-j'])

    return rule


with open('rules.txt', 'r') as f:
    for line in f.readlines():
        #print(line.strip())
        args = line.strip().split()
       	print 'args: ', args

 	cmdDic = initDic()
        if args[0] != 'iptables':
            continue
        chain_name = args[2]
        for i in range(3, len(args)):
            if args[i].startswith('-'):
		print args[i] 
		cmdDic[args[i]] = args[i+1]

        rule = createRule(cmdDic)
        chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), chain_name)
        chain.insert_rule(rule)
