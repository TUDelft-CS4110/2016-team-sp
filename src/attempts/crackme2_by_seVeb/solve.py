#!/usr/bin/env python2

import angr

start_addr = 0x400CE7 # Start of Main function
#find_addr = 0x400D77 # 2nd compare function requires d as first input
#find_addr = 0x400b68 # Pepper get past second compare
find_addr = 0x400aa4
avoid_addr = 0x400D8D # Start of hades function, when serial is invalid
input_addr = 0x602100
input_length = 21#0x15 # Derived from 0x400D66 where rax is string input_length


def extract_memory(state):
    """Convience method that returns the flag input memory."""
    return state.se.any_str(state.memory.load(input_addr, input_length))

def char(state, n):
    """Returns a symbolic BitVector and contrains it to printable chars for a given state."""
    vec = state.se.BVS('c{}'.format(n), 8, explicit_name=True)
    return vec, state.se.And(vec >= ord(' '), vec <= ord('~'))

def main():
    project = angr.Project('crackme02_64bit')
    
    print('input constraints')
    state = project.factory.blank_state(addr=start_addr)
    for i in range(input_length):
        c, cond = char(state, i)
        # the first command line argument is copied to INPUT_ADDR in memory
        # so we store the BitVectors for angr to manipulate
        state.memory.store(input_addr + i, c)
        state.add_constraints(cond)
        
    print('path and explorer')
    path = project.factory.path(state)
    explorer = project.surveyors.Explorer(start=path, find=(find_addr,), avoid=(avoid_addr,))
    
    print('run explorer')
    explorer.run()
    
    flag = extract_memory(explorer._f.state) # ex._f is equiv. to ex.found[0]
    print('found flag: {}'.format(flag))
    #for f in explorer.found:
    #    flag = flag = extract_memory(f.state)
    #    print('found flag: {}'.format(flag))

    return flag


if __name__ == '__main__':
    a = main()
    print [ord(c) for c in a]
    #print a
