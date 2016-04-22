#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import iptc

#It's not extensible, only used for match ip and ports
def initDic():
    d = {}
    d['-m'] = ''
    d['-p'] = ''
    d['-s'] = ''
    d['-d'] = ''
    d['-src-range'] = ''
    d['-dst-range'] = ''
    d['-sport'] = ''
    d['-dport'] = ''
    d['-j'] = ''
    return d

# no check for valid ipaddress range input
def createRule(cmdDic):
    rule = iptc.Rule()
    if cmdDic['-s'] != '':
        rule.src = cmdDic['-s']
    if cmdDic['-d'] != '':
        rule.dst = cmdDic['-p']
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

        for i in range(3, len(args)):
            if args[i].startswith('-'):
                print args[i]
                cmdDic[args[i]] = args[i+1]

        rule = createRule(cmdDic)
        if args[1] == '-A':
            chain_name = args[2]
            chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), chain_name)
            chain.append_rule(rule)
        if args[1] == '-I':
            chain_name = args[2]
            chain_position = int(args[3])
            chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), chain_name)
            chain.insert_rule(rule, chain_position)
        if args[1] == '-R':
            chain_name = args[2]
            chain_position = int(args[3])
            chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), chain_name)
            chain.replace_rule(rule, chain_position)
