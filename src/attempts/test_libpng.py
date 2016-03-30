import angr, simuvex
b = angr.Project('libpng-1.5.20/binary/lib/libpng15.so')
entry = b.entry
state = b.factory.blank_state(addr=entry)
sirsb = b.factory.sim_block(state)

# Print out all the actions for this block:
for sstmt in sirsb.statements:
     print '[+] Actions for statement %d' % sstmt.stmt_idx
     for a in sstmt.actions:
         if a.type == 'mem':
             print "Memory write to", a.addr.ast
             print "... address depends on registers", a.addr.reg_deps, "and temps", a.addr.tmp_deps
             print "... data is:", a.data.ast
             print "... data depends on registers", a.data.reg_deps, "and temps", a.data.tmp_deps
             if a.condition is not None:
                 print "... condition is:", a.condition.ast
             if a.fallback is not None:
                 print "... alternate write in case of condition fail:", a.fallback.ast
         elif a.type == 'reg':
             print 'Register write to registerfile offset', a.offset
             print "... data is:", a.data.ast
         elif a.type == 'tmp':
             print 'Tmp write to tmp', a.tmp
             print "... data is:", a.data.ast

# The list of successors:
print 'List of successors:'
for succ in sirsb.all_successors:
    print succ

# The default successor, i.e. the one that runs off the end of the block:
print 'default successor:'
print sirsb.default_exit

# Any unconstrained successors, that is, successors with symbolic instruction pointers:
print 'unconstrained successors:'
for succ in sirsb.unconstrained_successors:
    print succ

# Any successors whose constraints contain a contradition (not necessarily a complete list):
print 'successors whose constraints contain a contradiction:'
for succ in sirsb.unsat_successors:
    print succ
