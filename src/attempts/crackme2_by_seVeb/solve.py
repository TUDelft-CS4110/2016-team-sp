#!/usr/bin/env python2

import angr

start_addr = 0x400CE7 # Start of Main function
find_addr = 0x400E36 # Random address near the end of the program
avoid_addr = 0x400D8D # Start of hades function, when serial is invalid
input_addr = 0x602100 # Address where user inputted license key is stored
input_length = 21 #0x15 # Derived from 0x400D66 where rax is string input_length

project = angr.Project('crackme02_64bit') # Load crackme binary

print "Initialize solver"
special_conditions = []
print "-Set state of program to address: " + str(hex(start_addr))
state = project.factory.blank_state(addr=start_addr)
print "-Add constraints: "
for i in range(input_length):
    symb_vec = state.se.BVS("c"+str(i), 8, explicit_name=True) # Create a symbolic value for each character (8bits)
    constraint = state.se.And(symb_vec >= ord(' '), symb_vec <= ord('~')) # Each input character is between whitespace and ~
    if i >= 14 and i <= 17 :
        constraint = state.se.And(symb_vec % 2 == 0, state.se.And(symb_vec >= ord(' '), symb_vec <= ord('~')))
    state.memory.store(input_addr + i, symb_vec) # Put the symbolic value at the location of the character of the 'input string' 
    state.add_constraints(constraint) # Add constraint to the symbolic execution engine
    print "--"+str(constraint)
    
print "Initialize explorer"
path = project.factory.path(state) # Load a path for the explorer to start with, initialize at beginning of main.
print "-Path: "+str(path)
print "-Find addr: "+str(hex(find_addr))
print "-Avoid addr: "+str(hex(avoid_addr))
explorer = project.surveyors.Explorer(start=path, find=(find_addr,), avoid=(avoid_addr,))

print "Run explorer"
explorer.run()

print "Extract result from memory"
final_state = explorer.found[0].state
flag = final_state.se.any_str(final_state.memory.load(input_addr, input_length)) # Read the found serial from memory
print "license key: "+str(flag)
