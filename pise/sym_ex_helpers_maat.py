import logging
import time
import maat
from copy import deepcopy

class PISEEngine(maat.MaatEngine):
    def __init__(self, inputs, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.inputs = inputs
        self.idx = 0
        self.state_manager = maat.SimpleStateManager("./tmp")
        self.solvers = [maat.Solver()]

    def save_engine_state(self) -> None:
        self.state_manager.enqueue_state(self)
        sl = deepcopy(self.solver[-1])
        self.solvers.append(sl)

    def pop_engine_state(self) -> bool:
        self.solvers = self.solvers[:-1]
        return self.state_manager.dequeue_state(self)

    def branch_callback(self):
        cond = None
        if self.info.branch.taken:
            cond = self.info.branch.cond.invert()
        else:
            cond = self.info.branch.cond
        self.solvers[-1].add(cond)
        if self.solvers[-1].check():
            self.solvers[-1].pop()
            self.save_engine_state()
            self.solvers[-1].add(cond)
            self.vars.update_from(self.solvers[-1].get_model())
        return maat.ACTION.CONTINUE
