import os
import iprule

commands = ['-A', '-I', '-R', '-p', '-s', '-d', '-sport', '-dport', '-m', '-src-range', '-dst-range', '-j']

def createRule(cmdDic):
    rule = iprule.Rule()
    if '-s' in cmdDic:
        rule.src = cmdDic['-s']
    if '-d' in cmdDic:
        rule.dst = cmdDic['-d']
    if '-p' in cmdDic:
        rule.protocol = cmdDic['-p']
        match = iprule.Match(rule, cmdDic['-p'])
        if '-dport' in cmdDic:
            if cmdDic['-p'] != 'tcp' and cmdDic['-p'] != 'udp':
                print "port number only supported by tcp or udp protocol, the rule will be ignored"
                return None

            match.dport = cmdDic['-dport']
        if '-sport' in cmdDic:
            if cmdDic['-p'] != 'tcp' and cmdDic['-p'] != 'udp':
                print "port number only supported by tcp or udp protocol, the rule will be ignored"
                return None
            match.sport = cmdDic['-sport']
        rule.add_match(match)
    if '-m' in cmdDic:
        match = iprule.Match(rule, cmdDic['-m'])
        if '-src-range' in cmdDic:
            if '-s' in cmdDic:
                print "multiple '-s' flag not allowed, the rule will be ignored"
                return None
            match.src_range = cmdDic['-src-range']
        if '-dst-range' in cmdDic:
            if '-s' in cmdDic:
                print "multiple '-d' flag not allowed, the rule will be ignored"
                return None
            match.dst_range = cmdDic['-dst-range']
        rule.add_match(match)
    if '-j' in cmdDic:
        rule.target = cmdDic['-j']
    else:
        print "Target must be specified, the rule will be ignored"
        return None

    return rule

def setUp(file):
    table = iprule.Table(iprule.Table.FILTER)
    with open(file, 'r') as f:

        for line in f.readlines():
            right_cmds = True
            args = line.strip().split()
           	#print 'args: ', args
            cmdDic = dict()
            if args[0] != 'iptables':
                continue

            for i in range(1, len(args)):
                if args[i].startswith('-'):
                    if args[i] not in commands:
                        print "Invalid commands", args[i],  "the rule will be ignored"
                        right_cmds = False
                    cmdDic[args[i]] = args[i+1]

            if not right_cmds:
                continue

            rule = createRule(cmdDic)

            if rule == None:
                continue

            if args[1] == '-A':
                chain_name = args[2]
                chain = iprule.Chain(table, chain_name)
                chain.append_rule(rule)
                print "chain_A_len", len(chain._rules)
                #print "chain name", chain.name
                #print table.get_chain(chain_name).get_rule(0)._matches[0].dport
            if args[1] == '-I':
                chain_name = args[2]
                chain_position = int(args[3])
                chain = iprule.Chain(iprule.Table(iprule.Table.FILTER), chain_name)
                chain.insert_rule(rule, chain_position)
                print "chain_I_len", len(chain._rules)

            if args[1] == '-R':
                chain_name = args[2]
                chain_position = int(args[3])
                chain = iprule.Chain(iprule.Table(iprule.Table.FILTER), chain_name)
                chain.replace_rule(rule, chain_position)
                print "chain_R_len", len(chain._rules)

    return table
